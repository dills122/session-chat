import { Injectable } from '@angular/core';
import * as crypto from 'crypto-browserify';
import { SessionStorageService } from '../session-storage/session-storage.service';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {
  private user: crypto.DiffieHellman;

  constructor(private sessionStorageService: SessionStorageService) {}

  private generateUser() {
    this.user = crypto.getDiffieHellman('ecp20');
  }
  generateKeys() {
    if (!this.user) {
      this.generateUser();
    }
    this.generateKeys();
  }
}
