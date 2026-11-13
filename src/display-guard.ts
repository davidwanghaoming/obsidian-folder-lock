import {
  MarkdownView, MarkdownPreviewView, MarkdownRenderer, TextFileView, WorkspaceLeaf, TFile, setIcon,
  type App, type Plugin,
} from 'obsidian';
import { collapsedArgument, containsCiphertext, gatedOpen, patchMethod, safeMarkdown, type AnyMethod } from './guard-core';

export interface GuardHost {
  app: App;
  placeholder(): string;
  lockedFile(path: string): boolean;
  lockedFolder(path: string): boolean;
  openFile(path: string): Promise<boolean>;
  openFolder(path: string): Promise<boolean>;
  blockedView(path: string, leaf: WorkspaceLeaf): boolean;
  failed(kind: 'display' | 'explorer', error?: unknown): void;
}
const FAILSAFE = `
.folder-lock-view-unready .view-content { visibility:hidden !important; }
.folder-lock-view-unready::after { content:attr(data-folder-lock-placeholder); position:absolute; inset:50% 0 auto; text-align:center; }

html.folder-lock-index-pending .nav-folder-children { display:none !important; }
html.folder-lock-display-failsafe .workspace-leaf-content[data-type="markdown"] .view-content,
html.folder-lock-display-failsafe .markdown-embed-content,
html.folder-lock-display-failsafe .popover.hover-popover { visibility:hidden !important; }
html.folder-lock-display-failsafe .workspace-leaf-content[data-type="markdown"]::after {
content:attr(data-folder-lock-placeholder); position:absolute; inset:50% 0 auto; text-align:center; visibility:visible;
}
`;

/**
 * Core Markdown method wrappers sanitize BEFORE invoking Obsidian's renderer.
 * Explorer DOM/internal hooks are optional. No vault.read/cachedRead patch: other plugins
 * must NEVER accidentally save a sanitized placeholder over the real ciphertext.
 */
export class DisplayGuard {
  private cleanups: (() => void)[] = [];
  private rawViews = new Map<any, string>();
  private promptedViews = new WeakSet<object>();
  private enabled = true;
  private observer?: MutationObserver;
  private explorerPatched = new WeakSet<object>();
  private explorerWarned = false;
  private syncQueued = false;
  private diagnostics = new Set<string>();
  private unreadyViews = new WeakSet<object>();
  private rawSet?: AnyMethod;
  private style?: HTMLStyleElement;
  constructor(private plugin: Plugin, private host: GuardHost) {}
  emergencyShield(): void {
    document.documentElement.classList.add('folder-lock-display-failsafe');
    if (!this.style) {
      this.style = document.createElement('style'); this.style.textContent = FAILSAFE; document.head.appendChild(this.style);
    }
  }
  install(): void {
    this.emergencyShield();
    document.documentElement.classList.add('folder-lock-index-pending');
    const g = this;
    let coreReady = false;
    try {
      this.rawSet = MarkdownView.prototype.setViewData;
      this.cleanups.push(patchMethod(MarkdownView.prototype, 'setViewData', old => function(this: MarkdownView, data: string, clear: boolean) {
        if (!g.enabled) return old.call(this, data, clear);
        const blocked = containsCiphertext(data) || !!this.file && g.host.lockedFile(this.file.path);
        if (blocked) {
          g.rawViews.set(this, data);
          this.containerEl?.classList.add('folder-lock-shielded');
          this.containerEl?.setAttribute('data-folder-lock-placeholder', g.host.placeholder());
          try { old.call(this, g.host.placeholder(), true); g.unreadyViews.delete(this); this.containerEl?.classList.remove('folder-lock-view-unready'); } catch (error) { g.markUnready(this, error); return; }
          if (this.file && !g.promptedViews.has(this) && g.host.blockedView(this.file.path, this.leaf)) g.promptedViews.add(this);
          return;
        }
        g.rawViews.delete(this); g.promptedViews.delete(this); this.containerEl?.classList.remove('folder-lock-shielded');
        return old.call(this, data, clear);
      }));
      // Preserve raw data and suppress saves while a neutral placeholder is in an editor.
      this.cleanups.push(patchMethod(MarkdownView.prototype, 'getViewData', old => function(this: MarkdownView) {
        return g.rawViews.has(this) ? g.rawViews.get(this) : old.call(this);
      }));
      this.cleanups.push(patchMethod(TextFileView.prototype, 'save', old => function(this: TextFileView, ...args: any[]) {
        return g.rawViews.has(this) || this.containerEl?.classList.contains('folder-lock-view-unready') ? Promise.resolve() : old.apply(this, args);
      }));
      this.cleanups.push(patchMethod(MarkdownPreviewView.prototype, 'set', old => function(this: MarkdownPreviewView, data: string, clear: boolean) {
        return old.call(this, g.enabled ? safeMarkdown(data, g.host.placeholder(), !!this.file && g.host.lockedFile(this.file.path)) : data, clear);
      }));
      this.cleanups.push(patchMethod(MarkdownRenderer, 'render', old => function(this: unknown, app: App, text: string, el: HTMLElement, path: string, ...rest: any[]) {
        return old.call(this, app, g.enabled ? safeMarkdown(text, g.host.placeholder(), g.host.lockedFile(path)) : text, el, path, ...rest);
      }));
      if (typeof MarkdownRenderer.renderMarkdown === 'function') this.cleanups.push(patchMethod(MarkdownRenderer, 'renderMarkdown', old => function(this: unknown, text: string, el: HTMLElement, path: string, ...rest: any[]) {
        return old.call(this, g.enabled ? safeMarkdown(text, g.host.placeholder(), g.host.lockedFile(path)) : text, el, path, ...rest);
      }));
      // Public methods, wrapped (monkey-patching is not an officially guaranteed extension API).
      this.cleanups.push(patchMethod(WorkspaceLeaf.prototype, 'openFile', old => async function(this: WorkspaceLeaf, file: TFile, ...args: any[]) {
        if (!g.enabled || !/\.md$/i.test(file.path)) return old.call(this, file, ...args);
        return gatedOpen(() => g.host.openFile(file.path), () => old.call(this, file, ...args));
      }));
      this.cleanups.push(patchMethod(WorkspaceLeaf.prototype, 'setViewState', old => async function(this: WorkspaceLeaf, state: any, ...args: any[]) {
        const path = state?.state?.file;
        if (!g.enabled || typeof path !== 'string' || !/\.md$/i.test(path)) return old.call(this, state, ...args);
        return gatedOpen(() => g.host.openFile(path), () => old.call(this, state, ...args));
      }));
      coreReady = true;
    } catch (error) { this.reportOnce('display', error); }
    if (coreReady) document.documentElement.classList.remove('folder-lock-display-failsafe');
    this.plugin.registerMarkdownPostProcessor((el, context) => {
      if (this.host.lockedFile(context.sourcePath) || containsCiphertext(el.textContent ?? '')) {
        el.replaceChildren(document.createTextNode(this.host.placeholder())); el.classList.add('folder-lock-placeholder');
      }
    }, -10000);
    const click = (event: Event) => this.captureExplorer(event);
    for (const kind of ['click', 'dblclick', 'auxclick', 'keydown']) {
      document.addEventListener(kind, click, true);
      this.cleanups.push(() => document.removeEventListener(kind, click, true));
    }
    this.plugin.registerEvent(this.host.app.workspace.on('file-open', file => {
      if (file) this.checkExistingViews(file.path);
    }));
    this.plugin.registerEvent(this.host.app.workspace.on('active-leaf-change', leaf => {
      const view = leaf?.view;
      if (view instanceof MarkdownView && view.file) this.checkExistingViews(view.file.path);
    }));
    this.plugin.registerEvent(this.host.app.workspace.on('layout-change', () => this.scheduleSync()));
    this.observer = new MutationObserver(() => this.scheduleSync());
    this.observer.observe(document.body, { childList: true, subtree: true });
    this.sync();
  }
  ready(): void { document.documentElement.classList.remove('folder-lock-index-pending'); this.sync(); }
  private reportOnce(kind: 'display' | 'explorer', error?: unknown): void {
    const key = `${kind}:${error instanceof Error ? error.name + ':' + error.message : String(error ?? '')}`;
    if (this.diagnostics.has(key)) return;
    this.diagnostics.add(key);
    try { this.host.failed(kind, error); } catch { /* diagnostic rendering is best effort */ }
  }
  private failClosed(): void {
    try { document.documentElement.classList.add('folder-lock-display-failsafe'); } catch { /* DOM may be tearing down */ }
  }
  private markUnready(view: MarkdownView | undefined, error: unknown): void {
    try {
      if (view) this.unreadyViews.add(view);
      if (!view?.containerEl) this.failClosed();
      else {
        view.containerEl.classList.add('folder-lock-view-unready');
        view.containerEl.setAttribute('data-folder-lock-placeholder', this.host.placeholder());
      }
    } catch { this.failClosed(); }
    this.reportOnce('display', error);
  }
  private checkExistingViews(path?: string): void {
    this.host.app.workspace.iterateAllLeaves(leaf => {
      let view: MarkdownView | undefined;
      try {
        // A DeferredView is not a MarkdownView. Never force it to load during plugin startup.
        if (!(leaf.view instanceof MarkdownView) || !leaf.view.file || (path && leaf.view.file.path !== path)) return;
        view = leaf.view;
        view.containerEl.setAttribute('data-folder-lock-placeholder', this.host.placeholder());
        const data = view.getViewData();
        if (typeof data !== 'string') throw new TypeError('MarkdownView.getViewData() is not ready');
        const shield = containsCiphertext(data) || this.host.lockedFile(view.file!.path);
        if (shield && (!this.rawViews.has(view) || this.unreadyViews.has(view))) view.setViewData(data, true);
        else if (this.rawViews.has(view) && !this.promptedViews.has(view) && this.host.blockedView(view.file!.path, leaf)) this.promptedViews.add(view);
        if (!shield) this.unreadyViews.delete(view);
        if (!this.unreadyViews.has(view)) view.containerEl.classList.remove('folder-lock-view-unready');
      } catch (error) {
        // One unfinished editor must not abort plugin.onload(), other leaves, or UI registration.
        this.markUnready(view, error);
      }
    });
  }
  private scheduleSync(): void {
    if (this.syncQueued || !this.enabled) return;
    this.syncQueued = true;
    queueMicrotask(() => {
      this.syncQueued = false;
      if (this.enabled) { try { this.sync(); } catch (error) { this.failClosed(); this.reportOnce('display', error); } }
    });
  }
  sync(): void {
    if (!this.enabled) return;
    // Ignore mutations created by our own badges/collapse calls; otherwise an explorer rerender
    // can queue sync -> setCollapsed -> MutationObserver -> sync indefinitely during startup.
    this.observer?.disconnect();
    try { this.syncUnsafe(); } catch (error) { this.failClosed(); this.reportOnce('display', error); }
    finally {
      if (this.enabled && this.observer) {
        try { this.observer.observe(document.body, { childList: true, subtree: true }); }
        catch (error) { this.reportOnce('display', error); }
      }
    }
  }
  private syncUnsafe(): void {
    this.checkExistingViews();
    for (const title of document.querySelectorAll<HTMLElement>('.nav-folder-title[data-path], .nav-file-title[data-path]')) {
      const path = title.getAttribute('data-path') ?? '';
      const folder = title.classList.contains('nav-folder-title');
      const locked = folder ? this.host.lockedFolder(path) : this.host.lockedFile(path);
      const nav = folder ? title.closest<HTMLElement>('.nav-folder') : title.closest<HTMLElement>('.nav-file');
      nav?.classList.toggle('folder-lock-explorer-locked', locked);
      let badge = title.querySelector<HTMLElement>(':scope > .folder-lock-badge');
      if (locked && !badge) {
        badge = document.createElement('span'); badge.className = 'folder-lock-badge';
        badge.setAttribute('aria-label', this.host.placeholder()); setIcon(badge, 'lock'); title.appendChild(badge);
      } else if (!locked && badge) badge.remove();
      if (folder && locked && nav) {
        nav.classList.add('is-collapsed'); title.setAttribute('aria-expanded', 'false');
      }
    }
    const gHost = this.host;
    // Optional undocumented file-explorer model. If absent, DOM capture + CSS + file-open gate remain.
    try {
      for (const leaf of this.host.app.workspace.getLeavesOfType('file-explorer')) {
        const items = (leaf.view as unknown as { fileItems?: Record<string, any> }).fileItems;
        if (!items) { this.explorerWarning(); continue; }
        for (const [path, item] of Object.entries(items)) {
          if (typeof item?.setCollapsed !== 'function') continue;
          if (!this.explorerPatched.has(item)) {
            this.cleanups.push(patchMethod(item, 'setCollapsed', old => function(this: unknown, collapsed: boolean, ...args: any[]) {
              return old.call(this, collapsedArgument(collapsed, gHost.lockedFolder(item.file?.path ?? item.selfEl?.getAttribute?.('data-path') ?? path)), ...args);
            }));
            this.explorerPatched.add(item);
          }
          if (this.host.lockedFolder(path) && item.collapsed !== true) {
            const result = item.setCollapsed(true);
            if (result && typeof result.catch === 'function') result.catch((error: unknown) => this.explorerWarning(error));
          }
        }
      }
    } catch (error) { this.explorerWarning(error); }
  }
  private explorerWarning(error?: unknown): void {
    if (!this.explorerWarned || error) { this.explorerWarned = true; this.reportOnce('explorer', error); }
  }
  private captureExplorer(event: Event): void {
    if (!this.enabled || !(event.target instanceof Element)) return;
    if (event instanceof KeyboardEvent && !['Enter', ' ', 'ArrowRight'].includes(event.key)) return;
    const title = event.target.closest<HTMLElement>('.nav-folder-title[data-path], .nav-file-title[data-path]');
    if (!title) return;
    const path = title.getAttribute('data-path') ?? '';
    const folder = title.classList.contains('nav-folder-title');
    if (!(folder ? this.host.lockedFolder(path) : this.host.lockedFile(path))) return;
    event.preventDefault(); event.stopImmediatePropagation(); event.stopPropagation();
    if (event.type === 'dblclick' || event.type === 'auxclick') return;
    void (folder ? this.host.openFolder(path) : this.host.openFile(path)).then(async allowed => {
      this.sync();
      if (!allowed || !this.enabled) return;
      if (folder) {
        let expanded = false;
        try {
          for (const leaf of this.host.app.workspace.getLeavesOfType('file-explorer')) {
            const item = (leaf.view as any).fileItems?.[path];
            if (typeof item?.setCollapsed === 'function') { item.setCollapsed(false); expanded = true; }
          }
        } catch (error) { this.explorerWarning(error); }
        if (!expanded) title.click();
      } else {
        const file = this.host.app.vault.getAbstractFileByPath(path);
        if (file instanceof TFile) await this.host.app.workspace.getLeaf().openFile(file);
      }
    }).catch(() => { this.sync(); });
  }
  dispose(): void {
    this.enabled = false; this.observer?.disconnect();
    // Restore ORIGINAL ciphertext in memory before removing save guards; never autosave placeholders.
    for (const [view, raw] of this.rawViews) {
      try {
        if (containsCiphertext(raw)) this.rawSet?.call(view, raw, true);
        else {
          // A stale plaintext cache of a now-locked file must never be restored/saved on unload.
          view.save = () => Promise.resolve();
          view.leaf?.detach();
        }
      } catch { /* the view may already have been detached */ }
      view.containerEl?.classList.remove('folder-lock-shielded');
    }
    this.rawViews.clear();
    for (const cleanup of this.cleanups.reverse()) { try { cleanup(); } catch { /* another plugin may have patched later */ } }
    document.documentElement.classList.remove('folder-lock-display-failsafe', 'folder-lock-index-pending'); this.style?.remove();
    document.querySelectorAll('.folder-lock-badge').forEach(el => el.remove());
    document.querySelectorAll('.folder-lock-view-unready').forEach(el => el.classList.remove('folder-lock-view-unready'));
    document.querySelectorAll('.folder-lock-explorer-locked').forEach(el => el.classList.remove('folder-lock-explorer-locked'));
  }
}
