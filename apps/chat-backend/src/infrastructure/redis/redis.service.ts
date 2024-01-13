import { Inject, Injectable } from '@nestjs/common';

import { Room } from '../../interfaces/room';
import { hashString } from '../../shared/util';
import { RedisRepository } from './redis.repository';

@Injectable()
export class RedisService {
  constructor(@Inject(RedisRepository) private readonly redisRepository: RedisRepository) {}

  async setupRoom(roomId: string, leadParticipant: string) {
    const roomObj: Room = {
      id: roomId,
      participants: [leadParticipant],
      lead: leadParticipant,
      createdAt: new Date().toISOString(),
      everyoneJoined: false
    };
    await this.setRoomData(roomObj);
  }

  async setRoomData(room: Room) {
    await this.redisRepository.set(room.id, JSON.stringify(room));
  }

  async addParticipantToRoom(roomId: string, participant: string) {
    const roomObjStringy = await this.redisRepository.get(roomId);
    if (!roomObjStringy) {
      throw Error('No room found with given Id');
    }
    const roomObj: Room = JSON.parse(roomObjStringy);
    roomObj.participants.push(participant);
    roomObj.everyoneJoined = true; //TODO update this when more than 2 participants are allowed
    await this.setRoomData(roomObj);
  }

  async checkParticpantLink(link: string) {
    const linkHash: string = hashString(link);
    const linkValue = await this.redisRepository.get(linkHash);
    if (!linkValue) {
      return false;
    }
    return true;
  }

  async addParticpantLink(link: string) {
    const linkHash: string = hashString(link);
    await this.redisRepository.set(linkHash, 'true');
  }

  async removeParticpantLink(link: string) {
    const linkHash: string = hashString(link);
    await this.redisRepository.delete(linkHash);
  }
}
