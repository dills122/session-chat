import { Inject, Injectable } from '@nestjs/common';

import { RedisRepository } from './redis.repository';
import { Room } from 'src/interfaces/room';

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
}
