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

  displayFiles(files: Array<{ id: string; filename: string; size: number; created_at: string; jwt_token?: string; token?: string; public?: boolean; mime_type?: string }>) {
    if (files.length === 0) {
      this.filesList.innerHTML = '<p>файлы не найдены</p>';
      return;
    }

    this.filesList.innerHTML = files.map((file, index) => {
      const fileId = file.id.replace(/'/g, "\\'");
      const token = (file.jwt_token || file.token || '').replace(/'/g, "\\'");
      const filename = file.filename.replace(/'/g, "\\'");
      const mimeType = (file.mime_type || '').replace(/'/g, "\\'");
      return `
      <div class="file-item" data-file-index="${index}">
        <span>${this.escapeHtml(file.filename)}</span>
        <span>${this.formatSize(file.size)}</span>
        <span>${new Date(file.created_at).toLocaleString()}</span>
        <div class="file-actions">
          <button class="download-btn" data-file-id="${fileId}" data-file-token="${token}" data-file-name="${filename}" data-file-mime="${mimeType}">скачать</button>
          <button class="copy-link-btn" data-file-id="${fileId}" data-file-token="${token}">копировать ссылку</button>
          <button class="delete-btn" data-file-id="${fileId}">удалить</button>
        </div>
      </div>
    `;
    }).join('');

    this.filesList.querySelectorAll('.download-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        const fileId = target.getAttribute('data-file-id') || '';
        const token = target.getAttribute('data-file-token') || '';
        const filename = target.getAttribute('data-file-name') || '';
        const mimeType = target.getAttribute('data-file-mime') || '';
        const fileManager = (window as any).fileManager;
        if (fileManager) {
          fileManager.downloadFile(fileId, token, filename, mimeType);
        }
      });
    });

    this.filesList.querySelectorAll('.copy-link-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        const fileId = target.getAttribute('data-file-id') || '';
        const token = target.getAttribute('data-file-token') || '';
        const fileManager = (window as any).fileManager;
        if (fileManager) {
          fileManager.copyFileLink(fileId, token);
        }
      });
    });

    this.filesList.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        const fileId = target.getAttribute('data-file-id') || '';
        const fileManager = (window as any).fileManager;
        if (fileManager) {
          fileManager.deleteFile(fileId);
        }
      });
    });
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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
    const input = document.createElement('input');
    input.type = 'file';
    input.style.display = 'none';
    document.body.appendChild(input);

    this.uploadArea.setAttribute('role', 'button');
    this.uploadArea.setAttribute('tabindex', '0');

    this.uploadArea.addEventListener('click', () => {
      input.value = '';
      input.click();
    });

    this.uploadArea.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        input.value = '';
        input.click();
      }
    });

    input.addEventListener('change', () => {
      const files = input.files;
      if (files && files.length > 0) {
        onFileSelect(files[0]);
      }
    });

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
