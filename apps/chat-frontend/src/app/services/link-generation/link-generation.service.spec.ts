import { TestBed } from '@angular/core/testing';
import { CryptoService } from '../crypto/crypto.service';

import { LinkGenerationService } from './link-generation.service';

describe('LinkGenerationService', () => {
  let service: LinkGenerationService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [CryptoService]
    });
    service = TestBed.inject(LinkGenerationService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
