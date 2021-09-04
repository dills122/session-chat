import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { tap } from 'rxjs/operators';

import { LoginService } from 'src/app/services/login/login.service';

@Component({
  selector: 'td-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  private uid: string;
  private sessionHash: string;
  private sessionId: string;

  constructor(private loginService: LoginService, private router: Router, private route: ActivatedRoute) {}

  ngOnInit(): void {
    this.loginService.registerLoginCallback(this.uId);
    this.route.queryParamMap.pipe(
      tap((queryParam) => {
        this.sessionId = queryParam.get('sid');
        this.sessionHash = queryParam.get('hid');
        if (!(this.sessionId || this.sessionHash)) {
          this.router.navigate(['/home']);
        }
      })
    );
  }

  login() {
    console.log('Sending login event');
    this.loginService.login({
      roomId: this.sessionId,
      uid: this.uId
    });
  }

  get uId(): string {
    return this.uid;
  }

  set uId(val: string) {
    this.uid = val;
  }
}
