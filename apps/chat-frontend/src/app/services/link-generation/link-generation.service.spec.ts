import { TestBed } from '@angular/core/testing';

import { LinkGenerationService } from './link-generation.service';

describe('LinkGenerationService', () => {
  let service: LinkGenerationService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(LinkGenerationService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
