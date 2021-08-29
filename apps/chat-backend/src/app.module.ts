import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ChatGateway } from './chat/chat.gateway';
import { AlertGateway } from './alert/alert.gateway';
import { AlertController } from './alert/alert.controller';
import { JwtTokenService } from './services/jwt-token/jwt-token.service';

@Module({
  imports: [ConfigModule.forRoot()],
  controllers: [AlertController],
  providers: [ChatGateway, AlertGateway, JwtTokenService]
})
export class AppModule {}
