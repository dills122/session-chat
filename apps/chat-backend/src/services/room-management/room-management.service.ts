import { Inject, Injectable } from '@nestjs/common';
import { SessionCreation } from 'shared-sdk';
import { RedisService } from '../../infrastructure/redis/redis.service';

const nonLinkReferrerValues = ['re-auth', 'creator'];

@Injectable()
export class RoomManagementService {
  @Inject(RedisService)
  private readonly redisService: RedisService;

  isReferrerALink(referrer: string): boolean {
    return !nonLinkReferrerValues.includes(referrer);
  }

  async createSession(session: SessionCreation) {
    const { roomId, creatorUId, validParticipantLinks } = session;
    await this.redisService.setupRoom(roomId, creatorUId);
    for (const link of validParticipantLinks) {
      await this.redisService.addParticpantLink(link);
    }
  }

  async expireLink(referrer: string) {
    if (!this.isReferrerALink(referrer)) return;
    await this.redisService.removeParticpantLink(referrer);
  }

  async updateParticipantList(roomId: string, uid: string) {
    await this.redisService.addParticipantToRoom(roomId, uid);
  }

  async isParticipantLinkStillValid(referrer: string): Promise<boolean> {
    if (!this.isReferrerALink(referrer)) {
      return false;
    } else {
      const isGoodLink = await this.redisService.checkParticpantLink(referrer);
      return isGoodLink;
    }
  }
}
