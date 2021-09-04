import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'td-create-session',
  templateUrl: './create-session.component.html',
  styleUrls: ['./create-session.component.scss']
})
export class CreateSessionComponent implements OnInit {
  public participantUid: string;
  public ownersUid: string;
  constructor() {}

  ngOnInit(): void {}

  createSession() {}

  joinSession() {}
}
