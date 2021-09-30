import { Injectable } from '@angular/core';
import { CryptoService } from '../crypto/crypto.service';
import { HttpParams } from '@angular/common/http';
import { Observable, of } from 'rxjs';

export interface LinkHashPayload {
  uid: string;
  roomId: string;
}

export interface LinkHashVerificationPayload extends LinkHashPayload {
  hash: string;
}

@Injectable({
  providedIn: 'root'
})
export class LinkGenerationService {
  constructor(private cryptoService: CryptoService) {}

  createLinkForSession({ uid, roomId }: LinkHashPayload): Observable<string> {
    // TODO need check to see if link shortner service is running or not
    const params = new HttpParams().set('hash', this.createLinkHash({ uid, roomId })).set('rid', roomId);
    return of(`${location.origin}/login?${params.toString()}`);
  }

  createLinkHash({ uid, roomId }: LinkHashPayload) {
    return this.cryptoService.HashString(`${uid}-${roomId}`);
  }

  verifyHash({ uid, roomId, hash }: LinkHashVerificationPayload) {
    const generatedHash = this.createLinkHash({ uid, roomId });
    return hash === generatedHash;
  }
}
