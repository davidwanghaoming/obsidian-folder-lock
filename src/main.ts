import {
  App, FileView, Modal, Notice, Plugin, PluginSettingTab, Setting,
  TextFileView, TFile, TFolder, type WorkspaceLeaf, type Command,
} from 'obsidian';
import { createCredentials, isEncrypted, LockError, unlockKey, validateCredentials } from './crypto';
import { errorCode, normalizeFile, normalizeFolder, type Mode, type Store } from './engine';
import { newLockId, parseEnvelope } from './layers';
import {
  covers, inspect, isOuter, neededKeys, operationLocks, renameLocks, transformLocks,
  type LayerReport, type Lock, type State,
} from './lock-engine';
import { credentialsFromFiles, recoverHeaders } from './recovery';
import { DisplayGuard } from './display-guard';
import { translate, type Language, type MessageKey } from './i18n';

interface Data { version: 2; language: Language; idleMinutes: number; locks: Lock[] }
class UIError extends Error { constructor(readonly key: MessageKey) { super(key); } }
const defaults = (): Data => ({ version: 2, language: 'zh', idleMinutes: 0, locks: [] });
function parseData(raw: unknown): Data {
  if (raw === null || raw === undefined) return defaults();
  if (!raw || typeof raw !== 'object') throw new LockError('badMetadata');
  const value = raw as Record<string, unknown>;
  if (value.version !== 2 || (value.language !== 'zh' && value.language !== 'en') || !Array.isArray(value.locks) ||
      !Number.isInteger(value.idleMinutes) || (value.idleMinutes as number) < 0 || (value.idleMinutes as number) > 1440) {
    throw new LockError('badMetadata');
  }
  const locks = value.locks.map((v: unknown): Lock => {
    if (!v || typeof v !== 'object') throw new LockError('badMetadata');
    const l = v as Record<string, unknown>;
    if (typeof l.id !== 'string' || !/^[a-f0-9]{32}$/.test(l.id) || typeof l.path !== 'string' ||
        (l.type !== 'file' && l.type !== 'folder') ||
        (l.type === 'file' ? normalizeFile(l.path) : normalizeFolder(l.path)) !== l.path) throw new LockError('badMetadata');
    return { id: l.id, path: l.path, type: l.type, ...validateCredentials(l) };
  });
  if (new Set(locks.map(l => l.id)).size !== locks.length || new Set(locks.map(l => l.path)).size !== locks.length) {
    throw new LockError('badMetadata');
  }
  return { version: 2, language: value.language, idleMinutes: value.idleMinutes as number, locks };
}

export default class FolderLockPlugin extends Plugin {
  data: Data = defaults();
  state: State | null = null;
  lastReport: LayerReport | null = null;
  busy = false;
  disposed = false;
  fatal: MessageKey | null = null;
  private keys = new Map<string, CryptoKey>();
  private status!: HTMLElement;
  private ribbon!: HTMLElement;
  private settingsTab!: LockSettings;
  private lastActivity = Date.now();
  private autoFailed = false;
  private refreshTimer: number | undefined;
  private refreshSequence = 0;
  private warnedPlain = false;
  private pendingRenames: { oldPath: string; newPath: string }[] = [];
  private dialogs = new Set<Modal>();
  private display?: DisplayGuard;
  private knownEncrypted = new Set<string>();
  private headerLocks: Lock[] = [];
  private accessReady = false;
  private readyResolve!: () => void;
  private readyGate = new Promise<void>(resolve => { this.readyResolve = resolve; });
  private accessJobs = new Map<string, Promise<boolean>>();
  t = (key: MessageKey, values?: Record<string, string | number>): string => translate(this.data.language, key, values);
  get crypto(): Crypto { return window.crypto; }
  notice(key: MessageKey, values?: Record<string, string | number>): void { new Notice(this.t(key, values), 8000); }
  reason(error: unknown): string { return error instanceof UIError ? this.t(error.key) : this.t(`error_${errorCode(error)}`); }

  private startupDiagnostics = new Set<string>();
  private starting = false;
  private commandLabels: { command: Command; key: MessageKey; previous: string }[] = [];
  private addLabeledCommand(key: MessageKey, definition: Omit<Command, 'name'>): Command {
    const previous = this.t(key);
    const command = this.addCommand({ ...definition, name: previous });
    this.commandLabels.push({ command, key, previous });
    return command;
  }
  private relabelCommands(): void {
    for (const entry of this.commandLabels) {
      const next = this.t(entry.key);
      if (next === entry.previous) continue;
      this.startupSync('stageUi', () => {
        // Obsidian may prepend the plugin name to the public Command.name. Preserve it.
        const current = entry.command.name;
        const prefix = current.endsWith(entry.previous) ? current.slice(0, -entry.previous.length) : '';
        entry.command.name = prefix + next; entry.previous = next;
      });
    }
  }
  /** No password, key, header body or file content is logged, even when a hook throws. */
  private reportStartupError(stage: MessageKey, error: unknown): void {
    const name = error instanceof Error ? error.name : 'Error';
    const message = error instanceof Error ? error.message : typeof error === 'string' ? error : 'unknown error';
    const safe = `${name}: ${message}`.replace(/[\r\n]+/g, ' ')
      .replace(/(password|verifier|salt|ciphertext|key)\s*[:=]\s*\S+/gi, '$1=[redacted]').slice(0, 240);
    const id = `${stage}:${safe}`;
    if (this.startupDiagnostics.has(id)) return;
    this.startupDiagnostics.add(id);
    const text = this.t('startupFailure', { stage: this.t(stage), message: safe });
    const frames = error instanceof Error ? error.stack?.split('\n').filter(line => /^\s+at /.test(line)).slice(0, 4).join('\n') : '';
    try { console.error(text, frames ?? ''); } catch { /* diagnostics must never abort initialization */ }
    try { new Notice(text, 15000); } catch { /* console output remains available if Notice is unavailable */ }
  }
  private startupSync(stage: MessageKey, action: () => unknown): boolean {
    try { action(); return true; } catch (error) { this.reportStartupError(stage, error); return false; }
  }
  private async startupAsync(stage: MessageKey, action: () => Promise<unknown>): Promise<boolean> {
    try { await action(); return true; } catch (error) { this.reportStartupError(stage, error); return false; }
  }
  /** Register all recovery/control surfaces before touching views, configuration or vault contents. */
  private registerCoreUi(): void {
    const ui = (action: () => unknown) => this.startupSync('stageUi', action);
    ui(() => { this.ribbon = this.addRibbonIcon('lock', this.t('statusHelp'), () => { void this.run(this.primaryMode()); }); });
    ui(() => this.addLabeledCommand('lockCommand', { id: 'lock-all', callback: () => { void this.run('lock'); } }));
    ui(() => this.addLabeledCommand('unlockCommand', { id: 'unlock-all', callback: () => { void this.run('unlock'); } }));
    ui(() => this.addLabeledCommand('recover', { id: 'recover-headers', callback: () => { void this.recoverProtection(); } }));
    ui(() => this.addLabeledCommand('manageCommand', { id: 'choose-lock', callback: () => this.chooseLock() }));
    ui(() => this.addLabeledCommand('lockThisFile', { id: 'lock-current-file', checkCallback: checking => {
      const file = this.app.workspace.getActiveFile();
      if (!file || !/\.md$/i.test(file.path)) return false;
      if (!checking) {
        const lock = this.data.locks.find(l => l.path === file.path && l.type === 'file');
        if (lock) void this.run('lock', [lock.id]); else void this.addProtection(file.path);
      }
      return true;
    } }));
    ui(() => this.addLabeledCommand('unprotectCommand', { id: 'unprotect-current-file', checkCallback: checking => {
      const file = this.app.workspace.getActiveFile();
      const lock = file && this.data.locks.find(l => l.path === file.path && l.type === 'file');
      if (!lock) return false;
      if (!checking) void this.removeProtection(lock.id);
      return true;
    } }));
    ui(() => this.registerEvent(this.app.workspace.on('file-menu', (menu, file) => {
      this.startupSync('stageUi', () => {
        if (!(file instanceof TFolder) && !(file instanceof TFile && /\.md$/i.test(file.path))) return;
        const lock = this.data.locks.find(l => l.path === file.path);
        if (lock) {
          const mode = this.lockMode(lock.id);
          menu.addItem(item => item.setTitle(this.t(mode)).setIcon(mode === 'lock' ? 'lock' : 'unlock')
            .onClick(() => { void this.run(mode, [lock.id]); }));
          menu.addItem(item => item.setTitle(this.t('unprotectFile')).setIcon('x')
            .onClick(() => { void this.removeProtection(lock.id); }));
        } else {
          menu.addItem(item => item.setTitle(this.t(file instanceof TFolder ? 'protectFolder' : 'lockThisFile'))
            .setIcon('lock').onClick(() => { void this.addProtection(file.path); }));
        }
      });
    })));
    ui(() => { this.settingsTab = new LockSettings(this.app, this); this.addSettingTab(this.settingsTab); });
    ui(() => {
      this.status = this.addStatusBarItem();
      this.status.setAttribute('role', 'button'); this.status.tabIndex = 0;
      this.registerDomEvent(this.status, 'click', () => { void this.run(this.primaryMode()); });
      this.registerDomEvent(this.status, 'keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); void this.run(this.primaryMode()); }
      });
    });
  }
  private installDisplayGuard(): void {
    this.display = new DisplayGuard(this, {
      app: this.app, placeholder: () => this.t('lockedPlaceholder'),
      lockedFile: path => this.isFileLocked(path), lockedFolder: path => this.isFolderLocked(path),
      openFile: path => this.openProtectedFile(path), openFolder: path => this.openProtectedFolder(path),
      blockedView: (path, leaf) => {
        if (!this.accessReady || this.busy || this.disposed) return false;
        queueMicrotask(() => {
          void this.startupAsync('stageDisplay', async () => {
            const allowed = await this.openProtectedFile(path);
            if (this.disposed || !leaf.view) return;
            if (leaf.view instanceof FileView && leaf.view.file && leaf.view.file.path !== path) return;
            const file = this.app.vault.getAbstractFileByPath(path);
            if (allowed && file instanceof TFile) await leaf.openFile(file);
            else await leaf.setViewState({ type: 'empty' });
          });
        });
        return true;
      },
      failed: (kind, error) => {
        this.notice(kind === 'display' ? 'displayGuardFailed' : 'explorerFallback');
        if (error) this.reportStartupError('stageDisplay', error);
      },
    });
    this.display.install();
  }
  private registerRuntimeEvents(): void {
    const event = (action: () => unknown) => this.startupSync('stageEvents', action);
    const activity = () => { this.lastActivity = Date.now(); };
    for (const name of ['keydown', 'pointerdown', 'pointermove', 'touchstart', 'wheel'] as const) {
      event(() => this.registerDomEvent(document, name, activity, { passive: true }));
    }
    event(() => this.registerInterval(window.setInterval(() => {
      void this.startupAsync('stageEvents', () => this.checkIdle());
    }, 15_000)));
    event(() => this.registerEvent(this.app.vault.on('create', file => {
      void this.startupAsync('stageScan', () => this.updateEncryptedPath(file.path)); this.scheduleRefresh();
    })));
    event(() => this.registerEvent(this.app.vault.on('modify', file => {
      void this.startupAsync('stageScan', () => this.updateEncryptedPath(file.path)); this.scheduleRefresh();
    })));
    event(() => this.registerEvent(this.app.vault.on('delete', file => {
      this.knownEncrypted.delete(file.path); this.scheduleRefresh();
    })));
    event(() => this.registerEvent(this.app.vault.on('rename', (file, oldPath) => {
      this.startupSync('stageEvents', () => {
        for (const path of [...this.knownEncrypted]) if (path === oldPath || path.startsWith(`${oldPath}/`)) {
          this.knownEncrypted.delete(path); this.knownEncrypted.add(`${file.path}${path.slice(oldPath.length)}`);
        }
        this.pendingRenames.push({ oldPath, newPath: file.path }); void this.drainRenames();
      });
    })));
    event(() => this.register(() => { if (this.refreshTimer !== undefined) window.clearTimeout(this.refreshTimer); }));
  }
  async onload(): Promise<void> {
    this.starting = true;
    // A broken optional display/explorer hook must not remove the ribbon, menu, commands or settings.
    this.startupSync('stageUi', () => this.registerCoreUi());
    if (!this.startupSync('stageDisplay', () => this.installDisplayGuard())) {
      this.startupSync('stageDisplay', () => this.display?.emergencyShield());
    }
    try {
      const loaded = await this.startupAsync('stageConfig', async () => {
        const data = parseData(await this.loadData());
        if (data.locks.some(l => this.configPath(l.path))) throw new LockError('badMetadata');
        this.data = data;
      });
      if (!loaded) this.fatal = 'dataError';
      this.startupSync('stageCrypto', () => {
        if (!this.fatal && !window.crypto?.subtle) { this.fatal = 'webCryptoUnavailable'; this.notice(this.fatal); }
      });
      this.startupSync('stageEvents', () => this.registerRuntimeEvents());
      await this.startupAsync('stageScan', () => this.scanEncryptedPaths());
      await this.startupAsync('stageHeaders', () => this.updateHeaderCatalog(true));
    } catch (error) {
      this.reportStartupError('stageReady', error);
    } finally {
      this.starting = false; this.accessReady = true; this.readyResolve();
      this.startupSync('stageDisplay', () => this.display?.ready());
      this.startupSync('stageReady', () => this.updateUI());
    }
    this.startupSync('stageLayout', () => this.app.workspace.onLayoutReady(() => this.startupAsync('stageLayout', async () => {
      if (this.disposed) return;
      if (this.fatal) this.notice(this.fatal); else await this.refresh(true);
      this.display?.sync();
    })));
  }
  onunload(): void {
    this.disposed = true; this.readyResolve(); ++this.refreshSequence;
    try { this.startupSync('stageDisplay', () => this.display?.dispose()); }
    finally {
      const warn = this.busy || this.keys.size;
      this.keys.clear();
      if (warn) this.startupSync('stageReady', () => this.notice('stoppedWarning'));
      for (const modal of this.dialogs) this.startupSync('stageDisplay', () => modal.close());
      this.dialogs.clear();
    }
    // Never attempt asynchronous note writes during plugin unload.
  }
  private async updateEncryptedPath(path: string): Promise<void> {
    if (!/\.md$/i.test(path) || this.disposed) return;
    const file = this.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) return;
    try {
      if (isEncrypted(await this.app.vault.read(file))) this.knownEncrypted.add(path); else this.knownEncrypted.delete(path);
    } catch (error) { this.knownEncrypted.add(path); this.reportStartupError('stageScan', error); }
    if (!this.disposed) this.display?.sync();
  }
  private async scanEncryptedPaths(): Promise<void> {
    for (const file of this.app.vault.getMarkdownFiles()) await this.updateEncryptedPath(file.path);
  }
  isFileLocked(path: string): boolean {
    return this.knownEncrypted.has(path) || !!this.state?.files.find(f => f.path === path && f.layers.length);
  }
  isFolderLocked(path: string): boolean {
    if (this.headerLocks.some(l => l.type === 'folder' && (l.path === path || path.startsWith(`${l.path}/`)))) return true;
    return this.data.locks.some(lock => lock.type === 'folder' && (lock.path === path || path.startsWith(`${lock.path}/`)) && (
      (!this.state && this.data.locks.length > 0) || !!this.state?.locks.some(s => s.id === lock.id && (s.applied || s.blocked || s.errors)) ||
      [...this.knownEncrypted].some(file => covers(lock, file) && (!this.state || this.state.files.find(f => f.path === file)?.layers.includes(lock.id)))
    ));
  }
  private async updateHeaderCatalog(announce = false): Promise<void> {
    try {
      const catalog = await recoverHeaders(this.recoveryStore());
      if (!catalog.errors.length) this.headerLocks = catalog.locks;
      if (announce && catalog.legacyFiles.length) this.notice('legacyWarning');
      if (announce && catalog.errors.length) this.notice('recoveryFailed', { paths: catalog.errors.join('、') });
    } catch (error) { this.reportStartupError('stageHeaders', error); /* retain known locked scopes */ }
  }
  private recoveryStore(): Store {
    return {
      listFiles: () => this.app.vault.getFiles().map(file => file.path),
      hasFolder: path => this.app.vault.getAbstractFileByPath(path) instanceof TFolder,
      read: async path => {
        const file = this.app.vault.getAbstractFileByPath(path);
        if (!(file instanceof TFile)) throw new LockError('ioFailed');
        return this.app.vault.read(file);
      },
      compareAndWrite: async () => { throw new LockError('outsideFolder'); },
    };
  }
  async recoverProtection(): Promise<boolean> {
    if (this.disposed || this.busy || (this.fatal && this.fatal !== 'dataError')) return false;
    this.busy = true;
    try {
      const recovered = await recoverHeaders(this.recoveryStore(), this.data.locks);
      if (recovered.errors.length) { this.notice('recoveryFailed', { paths: recovered.errors.join('、') }); return false; }
      if (!recovered.found) { this.notice('noRecovery'); return false; }
      if (recovered.locks.some(l => this.configPath(l.path))) throw new LockError('outsideFolder');
      await this.persist({ ...this.data, locks: recovered.locks }, true);
      this.fatal = null; this.keys.clear();
      this.notice('recovered', { count: recovered.found });
      if (recovered.legacyFiles.length) this.notice('legacyWarning');
      return true;
    } catch (e) { new Notice(this.reason(e), 10000); return false; }
    finally { this.busy = false; if (!this.disposed) { this.updateUI(); await this.refresh(); } }
  }
  async openProtectedFile(path: string): Promise<boolean> {
    const prior = this.accessJobs.get(path); if (prior) return prior;
    const job = this.authorizeFile(path); this.accessJobs.set(path, job);
    try { return await job; } finally { this.accessJobs.delete(path); }
  }
  private async authorizeFile(path: string): Promise<boolean> {
    if (!this.accessReady) await this.readyGate;
    if (this.disposed) return false;
    const file = this.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) return false;
    try {
      let text = await this.app.vault.read(file);
      if (!isEncrypted(text)) { this.knownEncrypted.delete(path); return true; }
      this.knownEncrypted.add(path);
      let envelope = parseEnvelope(text)!;
      if (this.fatal === 'dataError' || envelope.layers.some(id => !this.data.locks.some(l => l.id === id))) {
        if (!envelope.headers.length) throw new LockError('legacyRecovery');
        if (!await this.recoverProtection()) return false;
      }
      for (let i = 0; i < 128 && isEncrypted(text); i++) {
        envelope = parseEnvelope(text)!;
        if (this.busy) return false;
        await this.run('unlock', [envelope.lockId]);
        const after = await this.app.vault.read(file);
        if (after === text) return false; // wrong password, cancellation or failed preflight
        text = after;
      }
      this.display?.sync(); return !isEncrypted(text);
    } catch (e) { if (!this.disposed) new Notice(this.reason(e), 10000); return false; }
  }
  async openProtectedFolder(path: string): Promise<boolean> {
    const tag = `folder:${path}`;
    const prior = this.accessJobs.get(tag); if (prior) return prior;
    const job = (async () => {
      if (!this.accessReady) await this.readyGate;
      if (this.disposed) return false;
      if (this.busy) return false;
      if (this.fatal === 'dataError' || this.headerLocks.some(h => (h.path === path || path.startsWith(`${h.path}/`)) && !this.data.locks.some(l => l.id === h.id))) {
        if (!await this.recoverProtection()) return false;
      }
      await this.refresh();
      for (const lock of this.data.locks.filter(l => l.type === 'folder' && (l.path === path || path.startsWith(`${l.path}/`)))
        .sort((a, b) => a.path.length - b.path.length)) {
        const s = this.state?.locks.find(s => s.id === lock.id);
        if (s && (s.applied || s.blocked || s.errors)) {
          await this.run('unlock', [lock.id]);
          const after = this.state?.locks.find(s => s.id === lock.id);
          if (!after || after.applied || after.blocked || after.errors) return false;
        }
      }
      this.display?.sync(); return !this.isFolderLocked(path);
    })();
    this.accessJobs.set(tag, job);
    try { return await job; } finally { this.accessJobs.delete(tag); }
  }
  private configPath(path: string): boolean {
    const dir = this.app.vault.configDir;
    return path === dir || path.startsWith(`${dir}/`) || dir.startsWith(`${path}/`);
  }
  private available(): boolean {
    if (this.disposed) return false;
    if (this.starting) { this.notice('busyHint'); return false; }
    if (this.fatal) { this.notice(this.fatal); return false; }
    if (this.busy) { this.notice('busyHint'); return false; }
    return true;
  }
  private store(locks: readonly Lock[] = this.data.locks): Store {
    const fileAt = (path: string): TFile => {
      if (!locks.some(l => covers(l, path)) || this.configPath(path)) throw new LockError('outsideFolder');
      const file = this.app.vault.getAbstractFileByPath(path);
      if (!(file instanceof TFile)) throw new LockError('ioFailed');
      return file;
    };
    return {
      listFiles: () => this.app.vault.getFiles().map(file => file.path),
      hasFolder: path => this.app.vault.getAbstractFileByPath(path) instanceof TFolder,
      read: async path => this.app.vault.read(fileAt(path)),
      compareAndWrite: async (path, expected, replacement) => {
        if (this.disposed) throw new LockError('cancelled');
        const file = fileAt(path);
        await this.app.vault.process(file, current => {
          if (this.disposed) throw new LockError('cancelled');
          if (file.path !== path || fileAt(path) !== file || current !== expected) throw new LockError('conflict');
          return replacement;
        });
        if (isEncrypted(replacement)) this.knownEncrypted.add(path); else this.knownEncrypted.delete(path);
      },
    };
  }
  private async persist(next: Data, recovery = false): Promise<void> {
    if (this.disposed || (this.fatal && !(recovery && this.fatal === 'dataError'))) throw new LockError('cancelled');
    // Explicit allowlist. The session map and passwords are NEVER serialized.
    await this.saveData({ version: 2, language: next.language, idleMinutes: next.idleMinutes,
      locks: next.locks.map(({ id, path, type, salt, verifier, iterations }) => ({ id, path, type, salt, verifier, iterations })),
    });
    if (this.disposed) throw new LockError('cancelled');
    this.data = next;
  }
  private scheduleRefresh(): void {
    if (this.disposed) return;
    if (this.refreshTimer !== undefined) window.clearTimeout(this.refreshTimer);
    this.refreshTimer = window.setTimeout(() => {
      this.refreshTimer = undefined; if (!this.busy) void this.refresh();
    }, 700);
  }
  private pruneKeys(): void {
    if (!this.state) return;
    for (const [id] of this.keys) {
      const s = this.state.locks.find(l => l.id === id);
      if (!s || (!s.clear && !s.errors)) this.keys.delete(id);
    }
  }
  async refresh(startup = false): Promise<void> {
    if (this.disposed || this.fatal || this.busy) return;
    const sequence = ++this.refreshSequence;
    try {
      await this.updateHeaderCatalog();
      const state = await inspect(this.store(), this.data.locks);
      if (this.disposed || this.busy || sequence !== this.refreshSequence) return;
      const oldSignature = this.state && JSON.stringify(this.state.locks);
      this.state = state;
      const plain = state.files.filter(f => !f.layers.length).length;
      if (plain && (startup || (!this.warnedPlain && this.data.locks.some(l => !this.keys.has(l.id))))) {
        this.notice(startup ? 'startupPlain' : 'unexpectedPlain', { count: plain }); this.warnedPlain = true;
      }
      if (!plain) this.warnedPlain = false;
      if (startup && state.errors.length) {
        this.notice('startupError');
        if (state.errors.some(e => e.code === 'headerMismatch')) this.notice('error_headerMismatch');
      }
      this.pruneKeys(); this.updateUI(oldSignature !== JSON.stringify(state.locks));
    } catch (error) {
      if (!this.disposed) { this.reportStartupError('stageRefresh', error); this.startupSync('stageUi', () => this.status?.setText(this.t('statusError'))); }
    }
  }
  lockMode(id: string): Mode {
    const state = this.state?.locks.find(s => s.id === id);
    return state && !state.clear && state.applied ? 'unlock' : 'lock';
  }
  primaryMode(): Mode { return this.state?.locks.some(s => s.clear) || !this.state?.files.length ? 'lock' : 'unlock'; }
  badge(id: string): string {
    const s = this.state?.locks.find(s => s.id === id);
    if (!s) return this.t('statusChecking');
    if (s.errors) return this.t('statusError');
    if (s.blocked) return this.t('blockedBadge');
    return this.t(s.clear ? (s.applied ? 'mixedBadge' : 'unlockedBadge') : s.applied ? 'lockedBadge' : 'emptyBadge');
  }
  private updateUI(refreshSettings = true): void {
    this.relabelCommands();
    if (!this.status) return;
    const s = this.state;
    const clear = s?.locks.filter(l => l.clear).length ?? 0;
    const text = this.fatal || s?.errors.length ? this.t('statusError') : this.busy ? this.t('statusBusy') :
      !s ? this.t('statusChecking') : !this.data.locks.length ? this.t('noLocks') :
      clear ? this.t(s.locks.some(l => l.applied) ? 'statusMixed' : 'statusPlain', { count: clear }) :
      this.t(s.files.length ? 'statusLocked' : 'statusEmpty', { count: this.data.locks.length });
    this.status.setText(text); this.status.setAttribute('aria-label', this.t('statusHelp'));
    this.ribbon?.setAttribute('aria-label', this.t('statusHelp'));
    this.startupSync('stageDisplay', () => this.display?.sync());
    if (refreshSettings) this.startupSync('stageUi', () => this.settingsTab?.redisplay());
  }
  private async promptPassword(lock: Lock, mode: Mode, verify = false): Promise<string | null> {
    const modal = new PasswordPrompt(this.app, this, lock, mode, verify); this.dialogs.add(modal);
    try { modal.open(); return await modal.result; } finally { this.dialogs.delete(modal); }
  }
  private async closeViews(locks: readonly Lock[]): Promise<void> {
    const leaves: WorkspaceLeaf[] = [];
    this.app.workspace.iterateAllLeaves(leaf => {
      const view = leaf.view;
      if (view instanceof FileView && view.file && /\.md$/i.test(view.file.path) && locks.some(l => covers(l, view.file!.path))) leaves.push(leaf);
    });
    for (const leaf of leaves) {
      if (this.disposed) throw new LockError('cancelled');
      if (leaf.view instanceof TextFileView) await leaf.view.save();
      await leaf.setViewState({ type: 'empty' });
    }
  }
  async run(mode: Mode, ids: readonly string[] = this.data.locks.map(l => l.id), automatic = false): Promise<void> {
    await this.drainRenames();
    if (!this.available()) return;
    if (!ids.length) { if (!automatic) this.notice('noLocks'); return; }
    this.busy = true; ++this.refreshSequence; this.updateUI();
    const candidates = new Map(this.keys);
    let phase: 'prepare' | 'write' = 'prepare';
    let authenticatingPath = '';
    try {
      const locks = this.data.locks.map(l => ({ ...l }));
      const store = this.store(locks);
      // All passwords authenticate before any editor save or note write.
      for (const id of await neededKeys(store, locks, ids, mode)) {
        if (candidates.has(id)) continue;
        if (automatic) throw new LockError('passwordNeeded');
        const lock = locks.find(l => l.id === id)!;
        authenticatingPath = lock.path;
        const password = await this.promptPassword(lock, mode);
        if (password === null || this.disposed) return;
        candidates.set(id, await unlockKey(password, await credentialsFromFiles(store, locks, id), this.crypto));
      }
      if (this.disposed) return;
      // GCM-authenticate the entire batch BEFORE saving/closing editors, including recovered headers.
      const check = await transformLocks(store, locks, ids, mode, candidates, this.crypto, this.t('lockedPlaceholder'),
        () => !this.disposed && !this.pendingRenames.length, true);
      if (check.failure) { this.lastReport = check; this.state = check.state; this.showReport(check); return; }
      phase = 'write'; // Editor saves may write plaintext before the encryption CAS phase.
      await this.closeViews(operationLocks(locks, ids, mode));
      const report = await transformLocks(store, locks, ids, mode, candidates, this.crypto,
        this.t('lockedPlaceholder'), () => !this.disposed && !this.pendingRenames.length);
      this.lastReport = report; this.state = report.state; await this.updateHeaderCatalog();
      if (!this.disposed) {
        this.keys = new Map(candidates); this.pruneKeys();
        new Notice(this.counts(report), 8000);
        if (report.failure || report.state.nonMarkdown.length) this.showReport(report);
        if (!report.failure && mode === 'unlock' && report.state.files.some(f => f.layers.length)) this.notice('retainedLayers');
        if (automatic && report.failure) { this.autoFailed = true; this.notice('autoFailed'); }
        else if (!automatic) this.autoFailed = false;
      }
    } catch (e) {
      if (!this.disposed) {
        if (e instanceof LockError && e.code === 'authFailed') {
          new Notice(this.t('resultFailure', { path: authenticatingPath, reason: this.reason(e) }), 10000);
        } else {
          // A failed discovery/read must name the affected file, not just display an opaque error.
          try {
            const state = await inspect(this.store(), this.data.locks);
            this.state = state;
            const failure = state.errors[0] ?? {
              path: this.data.locks.find(l => ids.includes(l.id))?.path ?? '', code: errorCode(e),
            };
            const report: LayerReport = { mode, changed: [], skipped: [], phase, state, failure };
            this.lastReport = report; this.showReport(report);
          } catch { new Notice(this.reason(e), 10000); }
        }
      }
      if (automatic) { this.autoFailed = true; this.notice('autoFailed'); }
    } finally {
      candidates.clear();
      this.busy = false; this.lastActivity = Date.now();
      if (!this.disposed) { await this.drainRenames(); this.updateUI(); this.scheduleRefresh(); }
    }
  }
  private async checkIdle(): Promise<void> {
    if (this.disposed || this.busy || this.autoFailed || !this.keys.size || !this.data.idleMinutes) return;
    if (Date.now() - this.lastActivity >= this.data.idleMinutes * 60_000) await this.run('lock', this.data.locks.map(l => l.id), true);
  }
  counts(r: LayerReport): string {
    return this.t('resultCounts', { locked: r.mode === 'lock' ? r.changed.length : 0,
      unlocked: r.mode === 'unlock' ? r.changed.length : 0, skipped: r.skipped.length });
  }
  showReport(report = this.lastReport): void {
    if (!report) return;
    const modal = new ResultModal(this.app, this, report); this.dialogs.add(modal);
    modal.onClose = () => { modal.contentEl.empty(); this.dialogs.delete(modal); }; modal.open();
  }
  chooseLock(): void {
    if (!this.available()) return;
    if (!this.data.locks.length) { this.notice('noLocks'); return; }
    const modal = new LockPicker(this.app, this); this.dialogs.add(modal);
    modal.onClose = () => { modal.contentEl.empty(); this.dialogs.delete(modal); }; modal.open();
  }
  async addProtection(input: string): Promise<void> {
    await this.drainRenames();
    if (!this.available()) return;
    let path: string;
    try { path = normalizeFolder(input); } catch { this.notice('invalidFolder'); return; }
    if (this.configPath(path)) { this.notice('invalidFolder'); return; }
    const file = this.app.vault.getAbstractFileByPath(path);
    const type = file instanceof TFolder ? 'folder' : file instanceof TFile && /\.md$/i.test(path) ? 'file' : null;
    if (!type) { this.notice('pathNotFound'); return; }
    if (this.data.locks.some(l => l.path === path)) { this.notice('duplicateLock'); return; }
    this.openPasswordEditor({ path, type });
  }
  openPasswordEditor(target: Lock | { path: string; type: 'file' | 'folder' }): void {
    if (!this.available()) return;
    const modal = new PasswordEditor(this.app, this, target); this.dialogs.add(modal);
    modal.afterClose = () => this.dialogs.delete(modal); modal.open();
  }
  async savePassword(target: Lock | { path: string; type: 'file' | 'folder' }, oldPassword: string, password: string): Promise<string> {
    await this.drainRenames();
    if (!this.available()) throw new LockError('cancelled');
    if (password.length < 8) throw new UIError('passwordShort');
    this.busy = true; ++this.refreshSequence; this.updateUI();
    try {
      const existing = 'id' in target ? this.data.locks.find(l => l.id === target.id) : undefined;
      if ('id' in target && !existing) throw new LockError('unknownLock');
      const path = existing?.path ?? target.path;
      const type = existing?.type ?? target.type;
      if (!existing && this.data.locks.some(l => l.path === path)) throw new UIError('duplicateLock');
      if (existing) await unlockKey(oldPassword, await credentialsFromFiles(this.store(), this.data.locks, existing.id), this.crypto);
      const file = this.app.vault.getAbstractFileByPath(path);
      if (this.configPath(path) || (type === 'folder' ? !(file instanceof TFolder) : !(file instanceof TFile))) throw new UIError('pathNotFound');
      const fresh = await createCredentials(password, this.crypto);
      const candidate: Lock = { id: existing?.id ?? newLockId(this.crypto), path, type, ...fresh.credentials };
      const state = await inspect(this.store(), this.data.locks);
      if (existing) {
        const s = state.locks.find(l => l.id === existing.id)!;
        if (s.applied || s.blocked || s.errors) throw new UIError('changeNeedsPlain');
      } else {
        const combined = [...this.data.locks, candidate];
        // Cannot introduce an inner layer behind an already-locked outer layer.
        const store = this.store(combined);
        for (const p of store.listFiles().filter(p => /\.md$/i.test(p) && covers(candidate, p))) {
          const envelope = parseEnvelope(await store.read(p));
          for (const id of envelope?.layers ?? []) {
            const outer = this.data.locks.find(l => l.id === id);
            if (!outer) throw new LockError('unknownLock');
            if (isOuter(outer, candidate)) throw new LockError('outerLocked');
          }
        }
      }
      if (this.pendingRenames.length) throw new LockError('conflict');
      await this.persist({ ...this.data, locks: existing ? this.data.locks.map(l => l.id === existing.id ? candidate : l) : [...this.data.locks, candidate] });
      this.keys.set(candidate.id, fresh.key); this.lastActivity = Date.now(); this.autoFailed = false;
      this.notice(existing ? 'passwordChanged' : 'protectedAdded');
      return candidate.id;
    } finally { this.busy = false; if (!this.disposed) { await this.drainRenames(); this.updateUI(); this.scheduleRefresh(); } }
  }
  async removeProtection(id: string): Promise<void> {
    await this.drainRenames();
    if (!this.available()) return;
    this.busy = true;
    try {
      const lock = this.data.locks.find(l => l.id === id); if (!lock) return;
      const password = await this.promptPassword(lock, 'unlock', true); if (password === null) return;
      await unlockKey(password, await credentialsFromFiles(this.store(), this.data.locks, id), this.crypto);
      const state = await inspect(this.store(), this.data.locks);
      const s = state.locks.find(l => l.id === id);
      if (!s) return;
      if (s.applied || s.blocked || s.errors) { this.notice('removeLockedFile'); return; }
      await this.persist({ ...this.data, locks: this.data.locks.filter(l => l.id !== id) }); this.keys.delete(id);
    } catch (e) { new Notice(this.reason(e)); }
    finally { this.busy = false; await this.drainRenames(); this.updateUI(); await this.refresh(); }
  }
  async setLanguage(language: Language): Promise<void> {
    if (!this.available()) return;
    this.busy = true;
    try { await this.persist({ ...this.data, language }); }
    catch (e) { new Notice(this.reason(e)); }
    finally { this.busy = false; await this.drainRenames(); this.updateUI(); }
  }
  async setIdle(value: string): Promise<void> {
    if (!this.available()) return;
    if (!/^\d+$/.test(value) || Number(value) > 1440) { this.notice('invalidIdle'); return; }
    this.busy = true;
    try { await this.persist({ ...this.data, idleMinutes: Number(value) }); this.lastActivity = Date.now(); this.autoFailed = false; }
    catch (e) { new Notice(this.reason(e)); }
    finally { this.busy = false; await this.drainRenames(); this.updateUI(); }
  }
  private async drainRenames(): Promise<void> {
    if (this.disposed || this.fatal || this.busy || !this.pendingRenames.length) return;
    this.busy = true; ++this.refreshSequence;
    try {
      while (this.pendingRenames.length && !this.disposed) {
        const { oldPath, newPath } = this.pendingRenames[0];
        const locks = renameLocks(this.data.locks, oldPath, newPath);
        const crossedBoundary = this.state?.files.some(file => {
          const moved = file.path === oldPath ? newPath : file.path.startsWith(`${oldPath}/`) ? `${newPath}${file.path.slice(oldPath.length)}` : file.path;
          return file.layers.some(id => { const lock = locks.find(l => l.id === id); return lock && !covers(lock, moved); });
        });
        if (crossedBoundary) this.notice('error_boundaryChanged');
        if (locks.some((l, i) => l.path !== this.data.locks[i].path)) {
          try {
            locks.forEach(l => {
              if ((l.type === 'file' ? normalizeFile(l.path) : normalizeFolder(l.path)) !== l.path || this.configPath(l.path)) throw new LockError('outsideFolder');
            });
          } catch { this.notice('renameUnsafe'); this.pendingRenames.shift(); continue; }
          if (new Set(locks.map(l => l.path)).size !== locks.length) throw new LockError('conflict');
          await this.persist({ ...this.data, locks });
        }
        this.pendingRenames.shift();
      }
    } catch { this.autoFailed = true; this.notice('renameFailed'); }
    finally { this.busy = false; if (!this.disposed) { this.updateUI(); this.scheduleRefresh(); } }
  }
}

class PasswordPrompt extends Modal {
  readonly result: Promise<string | null>;
  private resolve!: (value: string | null) => void;
  private input!: HTMLInputElement;
  constructor(app: App, private p: FolderLockPlugin, private lock: Lock, private mode: Mode, private verify = false) {
    super(app); this.result = new Promise(resolve => { this.resolve = resolve; });
  }
  onOpen(): void {
    const p = this.p;
    this.contentEl.addClass('folder-lock'); this.titleEl.setText(p.t(this.verify ? 'verifyPassword' : 'unlockTitle'));
    this.contentEl.createEl('p', { text: p.t('passwordPath', { path: this.lock.path }) });
    this.contentEl.createEl('p', { text: p.t(this.verify ? 'verifyHint' : this.mode === 'lock' ? 'lockPrompt' : 'unlockPrompt'), cls: 'folder-lock-hint' });
    const error = this.contentEl.createDiv({ cls: 'folder-lock-error' });
    new Setting(this.contentEl).setName(p.t('password')).addText(text => {
      this.input = text.inputEl; this.input.type = 'password'; this.input.autocomplete = 'off';
      this.input.setAttribute('aria-label', p.t('password'));
    });
    const submit = () => {
      if (!this.input.value) { error.setText(p.t('passwordRequired')); return; }
      this.resolve(this.input.value); this.close();
    };
    this.scope.register([], 'Enter', event => { event.preventDefault(); submit(); return false; });
    new Setting(this.contentEl).addButton(b => b.setButtonText(p.t('cancel')).onClick(() => this.close()))
      .addButton(b => b.setButtonText(p.t(this.verify ? 'verify' : this.mode)).setCta().onClick(submit));
    this.input.focus();
  }
  onClose(): void { if (this.input) this.input.value = ''; this.contentEl.empty(); this.resolve(null); }
}
class PasswordEditor extends Modal {
  afterClose?: () => void;
  private fields: HTMLInputElement[] = [];
  private submitting = false;
  constructor(app: App, private p: FolderLockPlugin, private target: Lock | { path: string; type: 'file' | 'folder' }) { super(app); }
  onOpen(): void {
    const p = this.p, changing = 'id' in this.target;
    this.contentEl.addClass('folder-lock'); this.titleEl.setText(p.t(changing ? 'changePassword' : 'setPassword'));
    this.contentEl.createEl('p', { text: p.t('passwordPath', { path: this.target.path }) });
    this.contentEl.createEl('p', { text: p.t(changing ? 'changeHint' : 'independentHint'), cls: 'folder-lock-hint' });
    this.contentEl.createEl('p', { text: p.t('passwordHint'), cls: 'folder-lock-hint' });
    const field = (label: MessageKey): HTMLInputElement => {
      let input!: HTMLInputElement;
      new Setting(this.contentEl).setName(p.t(label)).addText(text => {
        input = text.inputEl; input.type = 'password'; input.autocomplete = 'off';
        input.setAttribute('aria-label', p.t(label)); this.fields.push(input);
      }); return input;
    };
    const old = changing ? field('oldPassword') : null;
    const password = field('newPassword'), confirm = field('confirmPassword');
    const error = this.contentEl.createDiv({ cls: 'folder-lock-error' });
    const submit = async () => {
      if (this.submitting) return;
      if (password.value.length < 8) { error.setText(p.t('passwordShort')); return; }
      if (password.value !== confirm.value) { error.setText(p.t('passwordMismatch')); return; }
      this.submitting = true; error.setText(p.t('busy'));
      try {
        const id = await p.savePassword(this.target, old?.value ?? '', password.value);
        this.close(); if (!changing) await p.run('lock', [id]);
      } catch (e) { error.setText(p.reason(e)); }
      finally { this.submitting = false; }
    };
    this.scope.register([], 'Enter', event => { event.preventDefault(); void submit(); return false; });
    new Setting(this.contentEl).addButton(b => b.setButtonText(p.t('cancel')).onClick(() => this.close()))
      .addButton(b => b.setButtonText(p.t('save')).setCta().onClick(() => { void submit(); }));
    (old ?? password).focus();
  }
  onClose(): void { for (const input of this.fields) input.value = ''; this.contentEl.empty(); this.afterClose?.(); }
}
class LockPicker extends Modal {
  constructor(app: App, private p: FolderLockPlugin) { super(app); }
  onOpen(): void {
    this.contentEl.addClass('folder-lock'); this.titleEl.setText(this.p.t('locksTitle'));
    for (const lock of this.p.data.locks) lockRow(this.contentEl, this.p, lock, () => this.close());
  }
}
function lockRow(el: HTMLElement, p: FolderLockPlugin, lock: Lock, after?: () => void): void {
  const mode = p.lockMode(lock.id);
  new Setting(el).setName(lock.path).setDesc(p.t('itemState', { type: p.t(lock.type === 'folder' ? 'typeFolder' : 'typeFile'), state: p.badge(lock.id) }))
    .addButton(b => b.setButtonText(p.t(mode)).setDisabled(p.busy || !!p.state?.locks.find(s => s.id === lock.id)?.blocked).onClick(() => { after?.(); void p.run(mode, [lock.id]); }))
    .addExtraButton(b => b.setIcon('key-round').setTooltip(p.t('changePassword')).setDisabled(p.busy).onClick(() => { after?.(); p.openPasswordEditor(lock); }))
    .addExtraButton(b => b.setIcon('x').setTooltip(p.t('unprotectFile')).setDisabled(p.busy).onClick(() => { after?.(); void p.removeProtection(lock.id); }));
}
class ResultModal extends Modal {
  constructor(app: App, private p: FolderLockPlugin, private report: LayerReport) { super(app); }
  onOpen(): void {
    const p = this.p, r = this.report;
    this.contentEl.addClass('folder-lock'); this.titleEl.setText(p.t('resultTitle'));
    const body = this.contentEl.createDiv({ cls: 'folder-lock-report' });
    body.createEl('p', { text: p.counts(r) });
    if (r.failure) {
      body.createEl('p', { text: p.t('resultFailure', { path: r.failure.path, reason: p.t(`error_${r.failure.code}`) }), cls: 'folder-lock-error' });
      body.createEl('p', { text: p.t(r.phase === 'prepare' ? 'preflightFailed' : 'partialWarning') });
    }
    const list = (title: MessageKey, entries: string[]) => {
      new Setting(body).setName(p.t(title)).setHeading(); const ul = body.createEl('ul');
      if (!entries.length) ul.createEl('li', { text: p.t('noFiles') });
      for (const text of entries) ul.createEl('li', { text, cls: 'folder-lock-path' });
    };
    list('filesState', r.state.files.map(f => `${f.path} — ${p.t(f.layers.length ? 'layersCount' : 'plaintextBadge', { count: f.layers.length })}`));
    list('unreadableFiles', r.state.errors.map(e => `${e.path} — ${p.t(`error_${e.code}`)}`));
    list('attachments', r.state.nonMarkdown);
    new Setting(this.contentEl).addButton(b => b.setButtonText(p.t('close')).onClick(() => this.close()));
  }
}
class LockSettings extends PluginSettingTab {
  private showing = false;
  private draft = '';
  constructor(app: App, private p: FolderLockPlugin) { super(app, p); }
  hide(): void { this.showing = false; }
  redisplay(): void { if (this.showing) this.display(); }
  display(): void {
    this.showing = true;
    const p = this.p, el = this.containerEl;
    el.empty(); el.addClass('folder-lock');
    if (p.fatal) {
      el.createEl('p', { text: p.t(p.fatal), cls: 'folder-lock-error' });
      if (p.fatal === 'dataError') new Setting(el).setDesc(p.t('recoverHint')).addButton(b => b.setButtonText(p.t('recover')).onClick(() => { void p.recoverProtection(); }));
      return;
    }
    el.createEl('p', { text: p.t('independentHint'), cls: 'folder-lock-hint' });
    const mode = p.primaryMode();
    new Setting(el).setDesc(p.t('actionHint')).addButton(b =>
      b.setButtonText(p.t(mode === 'lock' ? 'globalLock' : 'globalUnlock')).setCta().setDisabled(p.busy || !p.data.locks.length)
        .onClick(() => { void p.run(p.primaryMode()); }));
    for (const lock of p.data.locks) lockRow(el, p, lock);
    if (!p.data.locks.length) el.createEl('p', { text: p.t('noLocks'), cls: 'folder-lock-hint' });
    new Setting(el).setDesc(p.t('addPathHint'))
      .addText(text => text.setPlaceholder(p.t('addPlaceholder')).setValue(this.draft).setDisabled(p.busy).onChange(v => { this.draft = v; }))
      .addButton(b => b.setButtonText(p.t('addProtection')).setDisabled(p.busy).onClick(() => { void p.addProtection(this.draft); }));
    new Setting(el).setName(p.t('idle')).setDesc(p.t('idleHint')).addText(text => {
      text.setValue(String(p.data.idleMinutes)).setDisabled(p.busy);
      text.inputEl.type = 'number'; text.inputEl.min = '0'; text.inputEl.max = '1440'; text.inputEl.step = '1';
      text.inputEl.setAttribute('aria-label', p.t('idleUnit'));
      text.inputEl.addEventListener('change', () => { void p.setIdle(text.getValue()); });
    });
    new Setting(el).setName(p.t('language')).addDropdown(d =>
      d.addOption('zh', p.t('languageZh')).addOption('en', p.t('languageEn')).setValue(p.data.language).setDisabled(p.busy)
        .onChange(v => { void p.setLanguage(v as Language); }));
    el.createEl('p', { text: p.t('coverageHint'), cls: 'folder-lock-hint' });
    el.createEl('p', { text: p.t('gitHint'), cls: 'folder-lock-hint' });
    for (const error of p.state?.errors ?? []) el.createEl('p', { text: `${error.path} — ${p.t(`error_${error.code}`)}`, cls: 'folder-lock-error' });
    new Setting(el).setDesc(p.t('recoverHint')).addButton(b => b.setButtonText(p.t('recover')).setDisabled(p.busy).onClick(() => { void p.recoverProtection(); }));
    if (p.lastReport) new Setting(el).addButton(b => b.setButtonText(p.t('lastReport')).onClick(() => p.showReport()));
  }
}
