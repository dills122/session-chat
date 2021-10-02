import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

export interface UrlShortnerResponse {
  shortCode: string;
  shortUrl: string;
  longUrl: string;
  dateCreated: string;
}

@Injectable()
export class UrlShortnerService {
  private baseUrl: string;
  private logger: Logger = new Logger('Url-Shortner-Service');
  constructor(private httpService: HttpService) {
    this.baseUrl = `${process.env.SHORT_DOMAIN_SCHEMA}://${process.env.SHORT_DOMAIN_HOST}`;
  }

  async createShortUrl(url: string): Promise<UrlShortnerResponse> {
    try {
      const resp = await firstValueFrom(
        this.httpService.post<UrlShortnerResponse>(
          `${this.baseUrl}/rest/v2/short-urls`,
          {
            longUrl: url
          },
          {
            headers: {
              'X-Api-Key': `{${process.env.URL_SHORTNER_API_KEY}}`
            }
          }
        )
      );
      if (resp.status !== 200) {
        throw Error('Failed response');
      }
      return resp.data;
    } catch (err) {
      this.logger.error(err);
      throw err;
    }
  }
}
