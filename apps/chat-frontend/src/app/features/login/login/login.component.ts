import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

import { LocalStorageService } from '../../../services/local-storage/local-storage.service';

@Component({
  selector: 'td-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  private username: string;

  constructor(private localStorageService: LocalStorageService, private router: Router) {}

  ngOnInit(): void {}

  login() {
    this.localStorageService.setItem('username', this.userName);
    this.router.navigate(['/chat-room']);
  }

  get userName(): string {
    return this.username;
  }

  set userName(val: string) {
    //do some extra work here
    this.username = val;
  }
}
