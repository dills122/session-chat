import { Injectable } from '@angular/core';
import * as Hasher from 'create-hash';
import * as RandomBytes from 'randombytes';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {
  private Hash: Hasher.HashAlgorithm;
  constructor() {
    this.Hash = Hasher('sha384');
  }

  HashString(input: string): string {
    this.Hash.update(input);
    return this.Hash.digest('hex');
  }

  GenerateRandomString() {
    return RandomBytes(24).toString('hex');
  }
}
