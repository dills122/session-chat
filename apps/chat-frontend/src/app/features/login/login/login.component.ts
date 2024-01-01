import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { NbGlobalPhysicalPosition, NbToastrService } from '@nebular/theme';

import { LoginService } from 'src/app/services/login/login.service';
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
    private toastrService: NbToastrService,
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
  }

  login() {
    if (!this.sessionId || !this.sessionHash) {
      this.toastrService.danger('Issue gathering required info from link', 'Login Issue', {
        position: NbGlobalPhysicalPosition.TOP_RIGHT
      });
    } else {
      try {
        this.createTimeoutwarningTimer();
        this.loginService.login({
          roomId: this.sessionId,
          uid: this.uId,
          hash: this.sessionHash
        });
      } catch (err) {
        this.utilService.clearTimeoutIfExists(this.timeoutId as string);
        this.toastrService.danger('Issue verifying participant data', 'Login Issue', {
          position: NbGlobalPhysicalPosition.TOP_RIGHT
        });
      }
    }
  }

  createTimeoutwarningTimer() {
    this.timeoutId = setTimeout(() => {
      this.toastrService.warning('Login is taking awhile, try refreshing', 'Timeout', {
        position: NbGlobalPhysicalPosition.TOP_RIGHT
      });
    }, 10000);
  }

  get uId(): string {
    return this.uid;
  }

  set uId(val: string) {
    this.uid = val;
  }
}
