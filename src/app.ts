import { ApiClient } from './api';
import { UIManager } from './ui';
import { FileManager } from './fileManager';

export class App {
  private api: ApiClient;
  private ui: UIManager;
  private fileManager: FileManager;

  constructor() {
    this.api = new ApiClient();
    this.ui = new UIManager();
    this.fileManager = new FileManager(this.api, this.ui);
  }

  async init() {
    await this.loadVersion();
    
    if (await this.api.checkToken()) {
      this.ui.showMain();
      await this.fileManager.loadFiles();
      await this.fileManager.loadStats();
    } else {
      this.api.clearToken();
      this.ui.showAuth();
    }

    this.setupEventListeners();
  }

  private async loadVersion() {
    try {
      const info = await this.api.getInfo();
      this.ui.showVersion(info.version);
    } catch (error) {
      console.error('Failed to load version:', error);
      this.ui.showVersion('idk');
    }
  }

  private setupEventListeners() {
    const addActivateListener = (el: HTMLElement | null, handler: () => void) => {
      if (!el) return;
      let activated = false;
      let lastTime = 0;
      const oncePerGesture = (e: Event) => {
        const now = Date.now();
        if (activated && now - lastTime < 400) return;
        activated = true;
        lastTime = now;
        handler();
        setTimeout(() => { activated = false; }, 400);
      };

      el.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        oncePerGesture(e);
      });
      el.addEventListener('pointerup', (e) => {
        e.preventDefault();
        e.stopPropagation();
        oncePerGesture(e);
      }, { passive: false } as any);
      el.addEventListener('touchend', (e) => {
        e.preventDefault();
        e.stopPropagation();
        oncePerGesture(e);
      }, { passive: false } as any);
    };

    const loginButton = document.getElementById('login-btn') as HTMLButtonElement;
    addActivateListener(loginButton, () => this.login());

    const logoutButton = document.getElementById('logout-btn') as HTMLButtonElement;
    addActivateListener(logoutButton, () => this.logout());

    const createTokenButton = document.getElementById('create-token-btn') as HTMLButtonElement;
    addActivateListener(createTokenButton, () => this.createPersonalToken());

    this.ui.setupUploadArea((file) => this.fileManager.uploadFile(file));

    (window as any).fileManager = this.fileManager;

    const tabs = Array.from(document.querySelectorAll('.tab-btn')) as HTMLButtonElement[];
    const panels = Array.from(document.querySelectorAll('[data-tab-panel]')) as HTMLElement[];
    const switchTab = (name: string) => {
      tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === name));
      panels.forEach(p => p.style.display = p.getAttribute('data-tab-panel') === name ? '' : 'none');
    };
    tabs.forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab || 'upload')));

    const pasteForm = document.getElementById('paste-form') as HTMLFormElement | null;
    const pasteContent = document.getElementById('paste-content') as HTMLTextAreaElement | null;
    const pasteSyntax = document.getElementById('paste-syntax') as HTMLSelectElement | null;
    const pasteTTL = document.getElementById('paste-ttl') as HTMLSelectElement | null;
    const pasteOnce = document.getElementById('paste-once') as HTMLInputElement | null;
    const pasteResult = document.getElementById('paste-result') as HTMLDivElement | null;
    if (pasteForm && pasteContent && pasteSyntax && pasteTTL && pasteOnce && pasteResult) {
      pasteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const content = pasteContent.value;
        if (!content) {
          this.ui.showError('пустая паста');
          return;
        }
        try {
          const res = await this.api.createPaste({
            content,
            syntax: pasteSyntax.value || undefined,
            ttl_sec: parseInt(pasteTTL.value, 10) || 0,
            once: pasteOnce.checked,
          });
          pasteResult.style.display = 'block';
          pasteResult.innerHTML = `<div>paste: <a href="${res.url}">${res.url}</a> | <a href="${res.raw_url}">raw</a></div>`;
          await navigator.clipboard.writeText(location.origin + res.raw_url);
          this.ui.showSuccess('ссылки скопированы');
        } catch (err) {
          this.ui.showError(err instanceof Error ? err.message : 'ошибка создания пасты');
        }
      });
    }
  }

  private async login() {
    const key = (document.getElementById('key-input') as HTMLInputElement).value;
    if (!key) {
      this.ui.showError('введите ключ');
      return;
    }

    try {
      await this.api.login(key);
      this.ui.showMain();
      await this.fileManager.loadFiles();
      await this.fileManager.loadStats();
    } catch (error) {
      this.ui.showError(error instanceof Error ? error.message : 'ошибка авторизации');
    }
  }

  private logout() {
    this.api.clearToken();
    this.ui.showAuth();
  }

  private async createPersonalToken() {
    const key = prompt('введите мастер-ключ для создания персонального токена:');
    if (!key) return;

    try {
      const result = await this.api.createPersonalToken(key);
      this.ui.showSuccess(`персональный токен создан: ${result.token}`);
      await navigator.clipboard.writeText(result.token);
    } catch (error) {
      this.ui.showError(error instanceof Error ? error.message : 'ошибка создания токена');
    }
  }
}

const app = new App();
app.init();