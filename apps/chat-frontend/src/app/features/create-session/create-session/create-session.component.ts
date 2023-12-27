import { Component } from '@angular/core';
import { CryptoService } from 'src/app/services/crypto/crypto.service';
import { LinkGenerationService } from 'src/app/services/link-generation/link-generation.service';
import { LoginService } from 'src/app/services/login/login.service';
import { Observable } from 'rxjs';
import { NbGlobalPhysicalPosition, NbToastrService } from '@nebular/theme';
import { UtilService } from 'src/app/services/util/util.service';
@Component({
  selector: 'td-create-session',
  templateUrl: './create-session.component.html',
  styleUrls: ['./create-session.component.scss']
})
export class CreateSessionComponent {
  public participantUid: string;
  public ownersUid: string;
  public linkUrl$: Observable<string>;
  public hasLinkBeenGenerated = false;
  public hasSessionBeenCreated = false;
  private roomId: string;
  timeoutId: unknown;
  constructor(
    private linkGenerationService: LinkGenerationService,
    private cryptoService: CryptoService,
    private loginService: LoginService,
    private toastrService: NbToastrService,
    private utilService: UtilService
  ) {}

  createSession() {
    this.generateRoomId();
    this.hasSessionBeenCreated = true;
  }

  joinSession() {
    if (!this.hasSessionBeenCreated) {
      // TODO show error notification
    }
    try {
      this.createTimeoutwarningTimer();
      this.loginService.registerLoginCallback(this.ownersUid, this.timeoutId);
      this.loginService.login({
        uid: this.ownersUid,
        roomId: this.roomId,
        hash: this.linkGenerationService.createLinkHash({ uid: this.ownersUid, roomId: this.roomId })
      });
    } catch (err) {
      console.error(err);
      this.utilService.clearTimeoutIfExists(this.timeoutId as string);
      this.toastrService.danger('Issue joining session', 'Login Issue', {
        position: NbGlobalPhysicalPosition.TOP_RIGHT
      });
    }
  }

  generateLink() {
    if (!this.hasSessionBeenCreated) {
      this.createSession();
    }
    this.togleLinkGeneration();
    if (this.hasSessionBeenCreated) {
      this.linkUrl$ = this.linkGenerationService.createLinkForSession({
        uid: this.participantUid,
        roomId: this.roomId
      });
    }
  }

  canJoinSession() {
    if (!this.hasLinkBeenGenerated || !this.hasSessionBeenCreated) {
      return false;
    }
    if (!this.ownersUid || this.ownersUid.length <= 0) {
      return false;
    }
    return true;
  }

  private generateRoomId() {
    this.roomId = this.cryptoService.GenerateRandomString();
  }

  togleLinkGeneration() {
    this.hasLinkBeenGenerated = !this.hasLinkBeenGenerated;
  }

  createTimeoutwarningTimer() {
    this.timeoutId = setTimeout(() => {
      this.toastrService.warning('Login is taking awhile, try refreshing', 'Timeout', {
        position: NbGlobalPhysicalPosition.TOP_RIGHT
      });
    }, 10000);
  }
}
