import { Injectable, Logger } from '@nestjs/common';

const nonLinkReferrerValues = ['re-auth', 'creator'];

@Injectable()
export class RoomManagementService {
  private logger: Logger = new Logger('RoomManagementService');

  updateParticipantList() {}

  isLinkExpired(referrer: string): boolean {
    if (nonLinkReferrerValues.includes(referrer)) {
      this.logger.warn('Non-link sent to isLinkExpired');
      return false;
    } else {
      //TODO check Redis Chatroom obj if this link has been used yet
      return false;
    }
  }
}
