import { HttpModule, HttpService } from '@nestjs/axios';
import { AxiosResponse } from 'axios';
import { Test, TestingModule } from '@nestjs/testing';
import { of } from 'rxjs';
import { UrlShortnerResponse, UrlShortnerService } from './url-shortner.service';

describe('UrlShortnerService', () => {
  let service: UrlShortnerService;
  let httpPostSpy: jest.SpyInstance;

  const data = {
    shortCode: 'short',
    shortUrl: 'short',
    longUrl: 'long',
    dateCreated: new Date().toISOString()
  } as UrlShortnerResponse;
  const response: AxiosResponse<UrlShortnerResponse> = {
    data,
    headers: {},
    config: { url: 'http://localhost:3000/mockUrl' },
    status: 200,
    statusText: 'OK'
  };
  beforeEach(async () => {
    httpPostSpy = jest.spyOn(HttpService.prototype, 'post').mockImplementation(() => of(response));
    const module: TestingModule = await Test.createTestingModule({
      providers: [UrlShortnerService],
      imports: [HttpModule]
    }).compile();

    service = module.get<UrlShortnerService>(UrlShortnerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should go through happy path and return response', async () => {
    const resp = await service.createShortUrl('test/url');
    expect(resp).toEqual(data);
  });

  it('should throw if return status is not 200', async () => {
    httpPostSpy.mockImplementation(() =>
      of({
        ...response,
        status: 403
      })
    );
    expect(service.createShortUrl('test/url')).rejects.toMatch('Failed response status');
  });
  it('should reject if http call returns error', async () => {
    httpPostSpy.mockRejectedValue('Err');
    expect(service.createShortUrl('test/url')).rejects.toMatch('Err');
  });
});
