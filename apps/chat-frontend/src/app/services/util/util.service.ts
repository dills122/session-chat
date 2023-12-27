import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class UtilService {
  constructor() {}

  clearTimeoutIfExists(timeoutId?: unknown) {
    if (!timeoutId) {
      return;
    }
    clearTimeout(timeoutId as string);
  }
}
