import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ChatGateway } from './chat/chat.gateway';
import { AlertGateway } from './alert/alert.gateway';
import { AlertController } from './alert/alert.controller';
import { JwtTokenService } from './services/jwt-token/jwt-token.service';
import { RoomManagementService } from './services/room-management/room-management.service';
import { RedisModule } from './infrastructure/redis/redis.module';
import { NotificationService } from './services/notification/notification.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '.env.development']
    }),
    RedisModule
  ],
  controllers: [AlertController],
  providers: [ChatGateway, AlertGateway, JwtTokenService, RoomManagementService, NotificationService]
})
export class AppModule {}
