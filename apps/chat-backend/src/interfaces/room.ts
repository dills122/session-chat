export interface Room {
  id: string;
  participants: string[];
  lead: string;
  createdAt: string;
  everyoneJoined: boolean;
}
