import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ChatGateway } from './chat/chat.gateway';
import { AlertGateway } from './alert/alert.gateway';
import { AlertController } from './alert/alert.controller';
import { JwtTokenService } from './services/jwt-token/jwt-token.service';
import { UrlShortnerService } from './services/url-shortner/url-shortner.service';
import { HttpModule } from '@nestjs/axios';
import { RedisService } from './services/redis-service/redis-service.service';
@Module({
  imports: [ConfigModule.forRoot(), HttpModule],
  controllers: [AlertController],
  providers: [ChatGateway, AlertGateway, JwtTokenService, UrlShortnerService, RedisService]
})
export class AppModule {}
