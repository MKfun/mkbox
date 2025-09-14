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
    const loginButton = document.getElementById('login-btn') as HTMLButtonElement;
    if (loginButton) {
      loginButton.onclick = () => this.login();
    }

    const logoutButton = document.getElementById('logout-btn') as HTMLButtonElement;
    if (logoutButton) {
      logoutButton.onclick = () => this.logout();
    }

    const createTokenButton = document.getElementById('create-token-btn') as HTMLButtonElement;
    if (createTokenButton) {
      createTokenButton.onclick = () => this.createPersonalToken();
    }

    this.ui.setupUploadArea((file) => this.fileManager.uploadFile(file));

    (window as any).fileManager = this.fileManager;
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