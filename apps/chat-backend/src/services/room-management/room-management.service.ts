import { Injectable, Logger } from '@nestjs/common';
import { SessionCreation } from 'shared-sdk';
import { RedisService } from 'src/infrastructure/redis/redis.service';

const nonLinkReferrerValues = ['re-auth', 'creator'];

@Injectable()
export class RoomManagementService {
  private logger: Logger = new Logger('RoomManagementService');

  constructor(private redisService: RedisService) {}

  async createSession(session: SessionCreation) {
    const { roomId, creatorUId, validParticipantLinks } = session;
    await this.redisService.setupRoom(roomId, creatorUId);
    for (const link of validParticipantLinks) {
      await this.redisService.addParticpantLink(link);
    }
  }

  async expireLink(link: string) {
    await this.redisService.removeParticpantLink(link);
  }

  async updateParticipantList(roomId: string, uid: string) {
    await this.redisService.addParticipantToRoom(roomId, uid);
  }

  async isLinkExpired(referrer: string): Promise<boolean> {
    if (nonLinkReferrerValues.includes(referrer)) {
      this.logger.warn('Non-link sent to isLinkExpired');
      return false;
    } else {
      const linkExists = await this.redisService.checkParticpantLink(referrer);
      return !!linkExists;
    }
  }
}
