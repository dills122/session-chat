import { HttpService } from '@nestjs/axios';
import { AxiosResponse } from 'axios';
import { Test, TestingModule } from '@nestjs/testing';
import { of } from 'rxjs';
import { UrlShortnerService } from './url-shortner.service';

// TODO need to learn how to write tests and why its getting dep injection issue
describe('UrlShortnerService', () => {
  let service: UrlShortnerService;
  let httpService: HttpService;

  beforeEach(async () => {
    const data = {
      shortCode: 'short',
      shortUrl: 'short',
      longUrl: 'long',
      dateCreated: new Date().toISOString()
    };
    const response: AxiosResponse<any> = {
      data,
      headers: {},
      config: { url: 'http://localhost:3000/mockUrl' },
      status: 200,
      statusText: 'OK'
    };
    const httpSpy = jest.spyOn(HttpService.prototype, 'get').mockReturnValue(of(response));
    const module: TestingModule = await Test.createTestingModule({
      providers: [UrlShortnerService],
      imports: [HttpService]
    }).compile();

    service = module.get<UrlShortnerService>(UrlShortnerService);
    httpService = module.get<HttpService>(HttpService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
