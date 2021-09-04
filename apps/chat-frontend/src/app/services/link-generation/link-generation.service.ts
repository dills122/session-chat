import { Injectable } from '@angular/core';
import { CryptoService } from '../crypto/crypto.service';
import { Router } from '@angular/router';
import { HttpParams } from '@angular/common/http';
import { Observable, of } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class LinkGenerationService {
  constructor(private cryptoService: CryptoService, private router: Router) {}

  createLinkForSession({ uid, roomId }: { uid: string; roomId: string }): Observable<string> {
    //TODO need check to see if link shortner service is running or not
    const params = new HttpParams()
      .set('hash', this.cryptoService.HashString(`${uid}-${roomId}`))
      .set('rid', roomId);
    return of(`${location.origin}/login?${params.toString()}`);
  }
}
