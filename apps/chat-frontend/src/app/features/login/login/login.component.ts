import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { NotificationTypes } from 'shared-sdk';

import { LoginService } from 'src/app/services/login/login.service';
import { NotificationServiceService } from 'src/app/services/notification/notification-service.service';
import { UtilService } from 'src/app/services/util/util.service';

@Component({
  selector: 'td-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  private uid: string;
  private sessionHash: string | null;
  private sessionId: string | null;
  private timeoutId: unknown;

  constructor(
    private loginService: LoginService,
    private notificationService: NotificationServiceService,
    private router: Router,
    private route: ActivatedRoute,
    private utilService: UtilService
  ) {}

  ngOnInit(): void {
    this.loginService.registerLoginCallback(this.uId, this.timeoutId);
    this.route.queryParamMap.subscribe((queryParams) => {
      this.sessionId = queryParams.get('rid');
      this.sessionHash = queryParams.get('hash');
      if (!this.sessionId || !this.sessionHash) {
        this.router.navigate(['/home']);
      }
    });
    //TODO implement guard to check link onLoad or something to see if its expired before even fully navigating to this view
  }

  login() {
    if (!this.sessionId || !this.sessionHash) {
      this.notificationService.showNotification(NotificationTypes.LOGIN_ISSUES);
    } else {
      try {
        this.createTimeoutwarningTimer();
        this.loginService.login({
          roomId: this.sessionId,
          uid: this.uId,
          hash: this.sessionHash,
          referrer: window.location.href
        });
      } catch (err) {
        this.utilService.clearTimeoutIfExists(this.timeoutId as string);
        this.notificationService.showNotification(NotificationTypes.LOGIN_ISSUES);
      }
    }
  }

  createTimeoutwarningTimer() {
    this.timeoutId = setTimeout(() => {
      this.notificationService.showNotification(NotificationTypes.LOGIN_TIMEOUT);
    }, 10000);
  }

  get uId(): string {
    return this.uid;
  }

  set uId(val: string) {
    this.uid = val;
  }
}
