import { ApiClient } from './api';
import { UIManager } from './ui';

export class FileManager {
  private api: ApiClient;
  private ui: UIManager;

  constructor(api: ApiClient, ui: UIManager) {
    this.api = api;
    this.ui = ui;
  }

  async downloadFile(fileId: string, fileToken: string) {
    if (fileToken && fileToken.length > 50) {
      const link = document.createElement('a');
      link.href = `/files/${fileId}`;
      link.style.display = 'none';
      document.body.appendChild(link);
      
      try {
        const response = await fetch(`/files/${fileId}`, {
          headers: {
            'X-File-Token': fileToken
          }
        });
        
        if (response.ok) {
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          link.href = url;
          link.download = '';
          link.click();
          window.URL.revokeObjectURL(url);
        } else {
          throw new Error('ошибка скачивания');
        }
      } catch (error) {
        this.ui.showError('ошибка скачивания файла');
      } finally {
        document.body.removeChild(link);
      }
    } else {
      const link = document.createElement('a');
      link.href = `/files/${fileId}?token=${fileToken}`;
      link.style.display = 'none';
      document.body.appendChild(link);
      
      try {
        const response = await fetch(`/files/${fileId}?token=${fileToken}`);
        
        if (response.ok) {
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          link.href = url;
          link.download = '';
          link.click();
          window.URL.revokeObjectURL(url);
        } else {
          throw new Error('ошибка скачивания');
        }
      } catch (error) {
        this.ui.showError('ошибка скачивания файла');
      } finally {
        document.body.removeChild(link);
      }
    }
  }

  async deleteFile(fileId: string) {
    if (!confirm('удалить файл?')) return;

    try {
      await this.api.deleteFile(fileId);
      this.ui.showSuccess('файл удален');
      await this.loadFiles();
      await this.loadStats();
    } catch (error) {
      this.ui.showError(error instanceof Error ? error.message : 'ошибка удаления');
    }
  }

  async copyFileLink(fileId: string, fileToken: string) {
    const fileUrl = `${window.location.origin}/files/${fileId}`;
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(fileUrl);
        this.ui.showSuccess('ссылка скопирована в буфер обмена');
      } else {
        this.fallbackCopyText(fileUrl);
      }
    } catch (error) {
      this.fallbackCopyText(fileUrl);
    }
  }

  private fallbackCopyText(text: string) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
      document.execCommand('copy');
      this.ui.showSuccess('ссылка скопирована в буфер обмена');
    } catch (err) {
      this.ui.showError('не удалось скопировать ссылку');
    }
    
    document.body.removeChild(textArea);
  }

  async uploadFile(file: File) {
    this.ui.showUploadProgress();

    try {
      await this.api.uploadFile(file, (percent) => {
        this.ui.updateUploadProgress(percent);
      });
      
      this.ui.hideUploadProgress();
      this.ui.showSuccess('файл загружен');
      
      
      await this.loadFiles();
      await this.loadStats();
    } catch (error) {
      this.ui.hideUploadProgress();
      this.ui.showError(error instanceof Error ? error.message : 'ошибка загрузки');
    }
  }

  async loadFiles() {
    try {
      const files = await this.api.getFiles();
      this.ui.displayFiles(files);
    } catch (error) {
      console.error('ошибка загрузки файлов:', error);
    }
  }

  async makePublic(fileId: string) {
    try {
      await this.api.makeFilePublic(fileId);
      this.ui.showSuccess('файл стал публичным');
      await this.loadFiles();
    } catch (error) {
      this.ui.showError(error instanceof Error ? error.message : 'ошибка публикации');
    }
  }

  async loadStats() {
    try {
      const stats = await this.api.getStats();
      this.ui.updateStats(stats.file_count, this.ui.formatSize(stats.total_size));
    } catch (error) {
      console.error('ошибка загрузки статистики:', error);
    }
  }
}
