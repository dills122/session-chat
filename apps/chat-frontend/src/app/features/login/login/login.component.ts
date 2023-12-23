import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';

import { LoginService } from 'src/app/services/login/login.service';

@Component({
  selector: 'td-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  private uid: string;
  private sessionHash: string | null;
  private sessionId: string | null;

  constructor(
    private loginService: LoginService,
    private router: Router,
    private route: ActivatedRoute
  ) {}

  ngOnInit(): void {
    this.loginService.registerLoginCallback(this.uId);
    this.route.queryParamMap.subscribe((queryParams) => {
      this.sessionId = queryParams.get('rid');
      this.sessionHash = queryParams.get('hash');
      if (!(this.sessionId || this.sessionHash)) {
        this.router.navigate(['/home']);
      }
    });
  }

  login() {
    if (!this.sessionId || !this.sessionHash) {
      //TODO maybe have toast error or just redirect
      return;
    }
    this.loginService.login({
      roomId: this.sessionId,
      uid: this.uId,
      hash: this.sessionHash
    });
  }

  get uId(): string {
    return this.uid;
  }

  set uId(val: string) {
    this.uid = val;
  }
}
