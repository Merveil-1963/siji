class BioAuth {
  static async register(deviceName = 'My Device') {
    try {
      const options = await this.fetchOptions('/bio/register/start/');
      const publicKey = {
        ...options,
        challenge: this.base64ToArrayBuffer(options.challenge),
        user: {
          ...options.user,
          id: this.base64ToArrayBuffer(options.user.id)
        }
      };
      
      const credential = await navigator.credentials.create({ publicKey });
      
      await this.sendToServer('/bio/register/finish/', {
        id: credential.id,
        rawId: this.arrayBufferToBase64(credential.rawId),
        response: {
          attestationObject: this.arrayBufferToBase64(credential.response.attestationObject),
          clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON)
        },
        device_name: deviceName
      });
      
      alert('Device registered successfully!');
    } catch (error) {
      console.error('Registration failed:', error);
      alert(`Registration failed: ${error.message}`);
    }
  }

  static async login(username) {
    try {
      const options = await this.fetchOptions(`/bio/login/start/?username=${encodeURIComponent(username)}`);
      const publicKey = {
        ...options,
        challenge: this.base64ToArrayBuffer(options.challenge),
        allowCredentials: options.allowCredentials.map(cred => ({
          ...cred,
          id: this.base64ToArrayBuffer(cred.id)
        }))
      };
      
      const assertion = await navigator.credentials.get({ publicKey });
      
      await this.sendToServer('/bio/login/finish/', {
        id: assertion.id,
        rawId: this.arrayBufferToBase64(assertion.rawId),
        response: {
          authenticatorData: this.arrayBufferToBase64(assertion.response.authenticatorData),
          clientDataJSON: this.arrayBufferToBase64(assertion.response.clientDataJSON),
          signature: this.arrayBufferToBase64(assertion.response.signature)
        }
      });
      
      window.location.href = '/dashboard/';
    } catch (error) {
      console.error('Login failed:', error);
      alert(`Login failed: ${error.message}`);
    }
  }

  static async fetchOptions(url) {
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': this.getCookie('csrftoken')
      }
    });
    
    if (!response.ok) {
      throw new Error(await response.text());
    }
    
    return response.json();
  }

  static async sendToServer(url, data) {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': this.getCookie('csrftoken')
      },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      throw new Error(await response.text());
    }
  }

  static base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  static arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    return btoa(String.fromCharCode(...bytes));
  }

  static getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }
}