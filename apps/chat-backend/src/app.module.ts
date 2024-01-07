import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ChatGateway } from './chat/chat.gateway';
import { AlertGateway } from './alert/alert.gateway';
import { AlertController } from './alert/alert.controller';
import { JwtTokenService } from './services/jwt-token/jwt-token.service';
import { RoomManagementService } from './services/room-management/room-management.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '.env.development']
    })
  ],
  controllers: [AlertController],
  providers: [ChatGateway, AlertGateway, JwtTokenService, RoomManagementService]
})
export class AppModule {}
