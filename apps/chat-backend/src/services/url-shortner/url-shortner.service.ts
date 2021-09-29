import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { AxiosResponse } from 'axios';
import { Observable } from 'rxjs';

export interface UrlShortnerResponse {
  shortCode: string;
  shortUrl: string;
  longUrl: string;
  dateCreated: string;
}

@Injectable()
export class UrlShortnerService {
  private baseUrl: string;
  constructor(private httpService: HttpService) {
    this.baseUrl = `${process.env.SHORT_DOMAIN_SCHEMA}://${process.env.SHORT_DOMAIN_HOST}`;
  }

  createShortUrl(url: string): Observable<AxiosResponse<UrlShortnerResponse>> {
    return this.httpService.post(
      `${this.baseUrl}/rest/v2/short-urls`,
      {
        longUrl: url
      },
      {
        headers: {
          'X-Api-Key': `{${process.env.URL_API_KEY}}`
        }
      }
    );
  }
}
