import { Injectable } from '@angular/core';
import * as Hasher from 'create-hash';
import * as RandomBytes from 'randombytes';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {
  private algorithm: Hasher.algorithm;
  constructor() {
    this.algorithm = 'sha384';
  }

  HashString(input: string): string {
    const hasher = Hasher(this.algorithm);
    hasher.update(input);
    const hash = hasher.digest('hex');
    return hash;
  }

  GenerateRandomString() {
    return RandomBytes(24).toString('hex');
  }
}
