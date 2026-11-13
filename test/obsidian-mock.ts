/** In-memory API double. This is NOT a real Obsidian runtime. */
export class TFile { constructor(public path: string) {} }
export class TFolder { constructor(public path: string) {} }
export class FileView { file: TFile | null = null; }
export class TextFileView extends FileView { saves = 0; async save(): Promise<void> { this.saves++; } }
export class MarkdownView extends TextFileView {
  data = ''; rendered: string[] = []; containerEl: HTMLElement; leaf: any;
  constructor() { super(); this.containerEl = globalThis.document?.createElement('div') as HTMLElement; }
  setViewData(data: string, _clear: boolean): void { this.data = data; this.rendered.push(data); }
  getViewData(): string { return this.data; }
}
export class MarkdownPreviewView { file: TFile | null = null; data = ''; set(data: string, _clear: boolean): void { this.data = data; } }
export class MarkdownRenderer {
  static async render(_app: unknown, text: string, el: HTMLElement): Promise<void> { el.textContent = text; }
  static async renderMarkdown(text: string, el: HTMLElement): Promise<void> { el.textContent = text; }
}
export class WorkspaceLeaf {
  detached = false; detach(): void { this.detached = true; }
  view: any = null; state: any = { type: 'empty' }; opens: string[] = [];
  async openFile(file: TFile): Promise<void> { this.opens.push(file.path); this.state = { type: 'markdown', state: { file: file.path } }; }
  async setViewState(state: any): Promise<void> { this.state = state; }
  getViewState(): any { return this.state; }
}
export function setIcon(el: HTMLElement, icon: string): void { el.textContent = icon; }
export class Notice {
  static messages: string[] = [];
  constructor(message: string, _timeout?: number) { Notice.messages.push(message); }
}
export class Plugin {
  app: any; saved: unknown = null; loaded: unknown = null;
  commands: any[] = []; ribbons: any[] = []; tabs: any[] = []; cleanups: (() => void)[] = [];
  async loadData(): Promise<unknown> { return this.loaded; }
  addRibbonIcon(icon: string, title: string, callback: () => void): HTMLElement {
    const el = document.createElement('div'); document.body.appendChild(el);
    this.ribbons.push({ icon, title, callback, el }); return el;
  }
  addCommand(command: any): any { this.commands.push(command); return command; }
  addSettingTab(tab: any): void { this.tabs.push(tab); }
  addStatusBarItem(): HTMLElement {
    const el = document.createElement('div') as HTMLElement & { setText(text: string): void };
    el.setText = text => { el.textContent = String(text); }; document.body.appendChild(el); return el;
  }
  register(callback: () => void): void { this.cleanups.push(callback); }
  registerDomEvent(el: any, name: string, callback: any, options?: any): void {
    el.addEventListener(name, callback, options); this.register(() => el.removeEventListener(name, callback, options));
  }
  registerInterval(_id: unknown): void {}
  postProcessor?: (el: HTMLElement, context: any) => void;
  async saveData(data: unknown): Promise<void> { this.saved = JSON.parse(JSON.stringify(data)); }
  registerMarkdownPostProcessor(fn: (el: HTMLElement, context: any) => void): void { this.postProcessor = fn; }
  registerEvent(_event: any): void {}
}
export class PluginSettingTab { constructor(..._args: any[]) {} }
export class Modal { constructor(..._args: any[]) {} }
export class Setting { constructor(..._args: any[]) {} }
