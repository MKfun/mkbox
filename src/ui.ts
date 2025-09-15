export class UIManager {
  private errorElement: HTMLElement;
  private successElement: HTMLElement;
  private authSection: HTMLElement;
  private mainSection: HTMLElement;
  private statusText: HTMLElement;
  private filesList: HTMLElement;
  private uploadArea: HTMLElement;
  private uploadProgress: HTMLElement;
  private progressFill: HTMLElement;
  private progressText: HTMLElement;
  private keyInput: HTMLInputElement;

  constructor() {
    this.errorElement = document.getElementById('error-message')!;
    this.successElement = document.getElementById('success-message')!;
    this.authSection = document.getElementById('auth-section')!;
    this.mainSection = document.getElementById('main-section')!;
    this.statusText = document.getElementById('status-text')!;
    this.filesList = document.getElementById('files-list')!;
    this.uploadArea = document.getElementById('upload-area')!;
    this.uploadProgress = document.getElementById('upload-progress')!;
    this.progressFill = document.getElementById('progress-fill')!;
    this.progressText = document.getElementById('progress-text')!;
    this.keyInput = document.getElementById('key-input') as HTMLInputElement;
  }

  showError(message: string) {
    this.errorElement.textContent = message;
    this.errorElement.style.display = 'block';
    this.successElement.style.display = 'none';
  }

  showSuccess(message: string) {
    this.successElement.textContent = message;
    this.successElement.style.display = 'block';
    this.errorElement.style.display = 'none';
  }

  showAuth() {
    this.authSection.style.display = 'flex';
    this.mainSection.style.display = 'none';
    this.keyInput.value = '';
  }

  showMain() {
    this.authSection.style.display = 'none';
    this.mainSection.style.display = 'block';
  }

  updateStats(fileCount: number, totalSize: string) {
    this.statusText.textContent = `сейчас залито ${fileCount} файлов. диск засрали на ${totalSize}.`;
  }

  displayFiles(files: Array<{ id: string; filename: string; size: number; created_at: string; jwt_token?: string; token?: string }>) {
    if (files.length === 0) {
      this.filesList.innerHTML = '<p>файлы не найдены</p>';
      return;
    }

    this.filesList.innerHTML = files.map(file => `
      <div class="file-item">
        <span>${file.filename}</span>
        <span>${this.formatSize(file.size)}</span>
        <span>${new Date(file.created_at).toLocaleString()}</span>
        <div class="file-actions">
          <button onclick="window.fileManager.downloadFile('${file.id}', '${file.jwt_token || file.token}')">скачать</button>
          <button onclick="window.fileManager.copyToken('${file.jwt_token || file.token}')">скопировать токен</button>
          <button onclick="window.fileManager.deleteFile('${file.id}')">удалить</button>
        </div>
      </div>
    `).join('');
  }

  showUploadProgress() {
    this.uploadProgress.style.display = 'block';
    this.progressFill.style.width = '0%';
    this.progressText.textContent = '0%';
  }

  hideUploadProgress() {
    this.uploadProgress.style.display = 'none';
  }

  updateUploadProgress(percent: number) {
    this.progressFill.style.width = percent + '%';
    this.progressText.textContent = Math.round(percent) + '%';
  }

  setupUploadArea(onFileSelect: (file: File) => void) {
    this.uploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      this.uploadArea.classList.add('dragover');
    });
    
    this.uploadArea.addEventListener('dragleave', () => {
      this.uploadArea.classList.remove('dragover');
    });
    
    this.uploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      this.uploadArea.classList.remove('dragover');
      
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        onFileSelect(files[0]);
      }
    });

    
  }

  formatSize(bytes: number): string {
    const sizes = ['B', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }

  showVersion(version: string) {
    const versionDisplay = document.getElementById('version-display');
    const versionText = document.getElementById('version-text');
    if (versionDisplay && versionText) {
      versionText.textContent = version;
      versionDisplay.style.display = 'block';
    }
  }
}
