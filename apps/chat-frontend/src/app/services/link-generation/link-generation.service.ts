import { Injectable } from '@angular/core';
import { CryptoService } from '../crypto/crypto.service';

@Injectable({
  providedIn: 'root'
})
export class LinkGenerationService {
  constructor(private cryptoService: CryptoService) {}

  createLinkForSession({ uid, roomId }: { uid: string; roomId: string }) {
    return this.cryptoService.HashString(`${uid}-${roomId}`);
  }
}
