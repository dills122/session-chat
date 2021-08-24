import { Component, OnInit } from '@angular/core';
import { AuthServiceService } from '../services/auth/auth-service.service';

@Component({
  selector: 'app-room-creation',
  templateUrl: './room-creation.component.html',
  styleUrls: ['./room-creation.component.scss']
})
export class RoomCreationComponent implements OnInit {
  constructor(private authService: AuthServiceService) {}

  ngOnInit(): void {
    this.authService.subscribeLogin().subscribe((msg) => console.log(msg));
    this.authService.attemptLogin({
      room: 'general',
      timestamp: new Date().toISOString(),
      uid: 'dsteele'
    });
  }
}
