import { Injectable } from '@angular/core';

const APP_PREFIX = 'ANMS-';

@Injectable({
  providedIn: 'root'
})
export class SessionStorageService {
  constructor() {}

  static loadInitialState() {
    return Object.keys(sessionStorage).reduce((state: any, storageKey) => {
      if (storageKey.includes(APP_PREFIX)) {
        const stateKeys = storageKey
          .replace(APP_PREFIX, '')
          .toLowerCase()
          .split('.')
          .map((key) =>
            key
              .split('-')
              .map((token, index) => (index === 0 ? token : token.charAt(0).toUpperCase() + token.slice(1)))
              .join('')
          );
        let currentStateRef = state;
        stateKeys.forEach((key, index) => {
          if (index === stateKeys.length - 1) {
            currentStateRef[key] = JSON.parse(sessionStorage.getItem(storageKey) || '{}');
            return;
          }
          currentStateRef[key] = currentStateRef[key] || {};
          currentStateRef = currentStateRef[key];
        });
      }
      return state;
    }, {});
  }

  setItem(key: string, value: any) {
    sessionStorage.setItem(`${APP_PREFIX}${key}`, JSON.stringify(value));
  }

  getItem(key: string) {
    return JSON.parse(sessionStorage.getItem(`${APP_PREFIX}${key}`) || '{}');
  }

  removeItem(key: string) {
    sessionStorage.removeItem(`${APP_PREFIX}${key}`);
  }

  setupSessionStorage({ room, token, uid }: { room: string; token: string; uid: string }) {
    this.setItem('room', room);
    this.setItem('jwt_token', token);
    this.setItem('uid', uid);
  }

  clearSessionStorage() {
    this.removeItem('room');
    this.removeItem('jwt_token');
    this.removeItem('uid');
  }

  /** Tests that sessionStorage exists, can be written to, and read from. */
  testSessionStorage() {
    const testValue = 'testValue';
    const testKey = 'testKey';
    const errorMessage = 'sessionStorage did not return expected value';

    this.setItem(testKey, testValue);
    const retrievedValue = this.getItem(testKey);
    this.removeItem(testKey);

    if (retrievedValue !== testValue) {
      throw new Error(errorMessage);
    }
  }
}
