export interface FileInfo {
  id: string;
  filename: string;
  size: number;
  created_at: string;
  jwt_token?: string;
  token?: string;
  public?: boolean;
}

export interface Stats {
  file_count: number;
  total_size: number;
}

export interface AuthResponse {
  token: string;
  personal_token: string;
}

export interface CreatePasteResponse {
  id: string;
  url: string;
  raw_url: string;
}

export interface CsrfResponse {
  token: string;
}

export class ApiClient {
  private token: string | null = null;
  private personalToken: string | null = null;

  constructor() {
    this.token = localStorage.getItem('mkbox_token');
    this.personalToken = localStorage.getItem('mkbox_personal_token');
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('mkbox_token', token);
  }

  setPersonalToken(personalToken: string) {
    this.personalToken = personalToken;
    localStorage.setItem('mkbox_personal_token', personalToken);
  }

  clearToken() {
    this.token = null;
    this.personalToken = null;
    localStorage.removeItem('mkbox_token');
    localStorage.removeItem('mkbox_personal_token');
  }

  private async getCsrfToken(): Promise<string> {
    const response = await fetch('/csrf-token');
    const data: CsrfResponse = await response.json();
    return data.token;
  }

  private getAuthHeaders(): HeadersInit {
    const headers: HeadersInit = {};
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    if (this.personalToken) {
      headers['X-Personal-Token'] = this.personalToken;
    }
    return headers;
  }

  async checkToken(): Promise<boolean> {
    if (!this.token || !this.personalToken) return false;

    try {
      const response = await fetch('/api/stats', {
        headers: this.getAuthHeaders()
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async login(key: string): Promise<AuthResponse> {
    const csrfToken = await this.getCsrfToken();
    
    const response = await fetch('/auth', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify({ key })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'ошибка авторизации');
    }

    this.setToken(data.token);
    this.setPersonalToken(data.personal_token);
    return data;
  }

  async getStats(): Promise<Stats> {
    const response = await fetch('/api/stats', {
      headers: this.getAuthHeaders()
    });

    if (!response.ok) {
      throw new Error('ошибка загрузки статистики');
    }

    return response.json();
  }

  async getFiles(): Promise<FileInfo[]> {
    const response = await fetch('/api/files', {
      headers: this.getAuthHeaders()
    });

    if (!response.ok) {
      throw new Error('ошибка загрузки файлов');
    }

    return response.json();
  }

  async deleteFile(fileId: string): Promise<void> {
    const csrfToken = await this.getCsrfToken();
    
    const response = await fetch(`/files/${fileId}`, {
      method: 'DELETE',
      headers: {
        ...this.getAuthHeaders(),
        'X-CSRF-Token': csrfToken
      }
    });

    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error || 'ошибка удаления');
    }
  }

  async makeFilePublic(fileId: string): Promise<void> {
    const csrfToken = await this.getCsrfToken();
    const response = await fetch(`/files/${fileId}/public`, {
      method: 'POST',
      headers: {
        ...this.getAuthHeaders(),
        'X-CSRF-Token': csrfToken
      }
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || 'ошибка публикации файла');
    }
  }

  async createPersonalToken(key: string): Promise<{ token: string }> {
    const csrfToken = await this.getCsrfToken();
    
    const response = await fetch('/create-token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify({ key })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'ошибка создания токена');
    }

    return data;
  }

  async uploadFile(file: File, onProgress: (percent: number) => void): Promise<void> {
    const formData = new FormData();
    formData.append('file', file);

    const csrfToken = await this.getCsrfToken();
    
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percentComplete = (e.loaded / e.total) * 100;
          onProgress(percentComplete);
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status === 200) {
          resolve();
        } else {
          try {
            const data = JSON.parse(xhr.responseText);
            reject(new Error(data.error || 'ошибка загрузки'));
          } catch {
            reject(new Error('ошибка загрузки'));
          }
        }
      });

      xhr.addEventListener('error', () => {
        reject(new Error('ошибка сети'));
      });

      xhr.open('POST', '/upload');
      xhr.setRequestHeader('Authorization', `Bearer ${this.token}`);
      xhr.setRequestHeader('X-CSRF-Token', csrfToken);
      if (this.personalToken) {
        xhr.setRequestHeader('X-Personal-Token', this.personalToken);
      }
      xhr.send(formData);
    });
  }

  async getInfo(): Promise<{ version: string }> {
    const response = await fetch('/api/info');
    if (!response.ok) {
      throw new Error('Failed to get info');
    }
    return response.json();
  }

  async createPaste(params: { content: string; syntax?: string; ttl_sec?: number; once?: boolean }): Promise<CreatePasteResponse> {
    const csrfToken = await this.getCsrfToken();
    const response = await fetch('/api/paste', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify(params)
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'ошибка создания пасты');
    }
    return data;
  }
}
