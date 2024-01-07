import { Component, ViewChild } from '@angular/core';
import { NbGlobalPhysicalPosition, NbToastrService } from '@nebular/theme';
import { Observable, catchError, of } from 'rxjs';
import { ConfirmModalComponent } from 'src/app/core/confirm-modal/confirm-modal.component';
import { CryptoService } from 'src/app/services/crypto/crypto.service';
import { LinkGenerationService } from 'src/app/services/link-generation/link-generation.service';
import { LoginService } from 'src/app/services/login/login.service';
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
  @ViewChild('session_confirmation') private modalComponent: ConfirmModalComponent;
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

  verifyConfirmModalResult(event: boolean) {
    if (event) {
      this.joinSession();
    }
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
        hash: this.linkGenerationService.createLinkHash({ uid: this.ownersUid, roomId: this.roomId }),
        referrer: 'creator'
      });
    } catch (err) {
      console.error(err);
      this.utilService.clearTimeoutIfExists(this.timeoutId as string);
      this.toastrService.danger('Issue joining session', 'Login Issue', {
        position: NbGlobalPhysicalPosition.TOP_RIGHT
      });
    }
  }

  openConfirmationModal() {
    this.modalComponent.open();
  }

  generateLink() {
    if (!this.hasSessionBeenCreated) {
      this.createSession();
    }
    this.togleLinkGeneration();
    if (this.hasSessionBeenCreated) {
      this.linkUrl$ = this.linkGenerationService
        .createLinkForSession({
          uid: this.participantUid,
          roomId: this.roomId
        })
        .pipe(
          catchError((err) => {
            //TODO update with toast after UI lib upgrade
            console.warn(err);
            return of();
          })
        );
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
