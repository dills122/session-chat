import { Component, ElementRef, OnInit, ViewChild } from '@angular/core';
import { NbGlobalPhysicalPosition, NbToastrService } from '@nebular/theme';
import { Observable, catchError, of } from 'rxjs';
import { EventStatuses } from 'shared-sdk';
import { ConfirmModalComponent } from 'src/app/core/confirm-modal/confirm-modal.component';
import { CryptoService } from 'src/app/services/crypto/crypto.service';
import { LinkGenerationService } from 'src/app/services/link-generation/link-generation.service';
import { LoginService } from 'src/app/services/login/login.service';
import { RoomManagementService } from 'src/app/services/room-management/room-management.service';
import { UtilService } from 'src/app/services/util/util.service';
@Component({
  selector: 'td-create-session',
  templateUrl: './create-session.component.html',
  styleUrls: ['./create-session.component.scss']
})
export class CreateSessionComponent implements OnInit {
  public participantUid: string;
  public ownersUid: string;
  public linkUrl$: Observable<string>;
  public hasLinkBeenGenerated = false;
  public hasSessionBeenCreated = false;
  public hasRoomIdBeenCreated = false;
  private roomId: string;
  timeoutId: unknown;
  @ViewChild('session_confirmation') private modalComponent: ConfirmModalComponent;
  @ViewChild('generated_link') private linkComponent: ElementRef;
  constructor(
    private linkGenerationService: LinkGenerationService,
    private cryptoService: CryptoService,
    private loginService: LoginService,
    private toastrService: NbToastrService,
    private utilService: UtilService,
    private roomManagementService: RoomManagementService
  ) {}
  ngOnInit(): void {
    this.generateRoomId();
    this.roomManagementService.subscribeSessionCreation().subscribe((resp) => {
      if (resp.status === EventStatuses.SUCCESS) {
        this.hasSessionBeenCreated = true;
        this.joinSession();
      } else {
        this.hasSessionBeenCreated = false;
        this.toastrService.danger('Issue creating session, try again later', 'Session Creation Issue', {
          position: NbGlobalPhysicalPosition.TOP_RIGHT
        });
      }
    });
  }

  createSession() {
    const participantLink = (this.linkComponent.nativeElement as HTMLInputElement).value;
    this.roomManagementService.createSession({
      roomId: this.roomId,
      creatorUId: this.ownersUid,
      validParticipantLinks: [participantLink]
    });
  }

  verifyConfirmModalResult(event: boolean) {
    if (event) {
      this.createSession();
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
    this.togleLinkGeneration();
    if (this.hasRoomIdBeenCreated) {
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

  canCreateSession() {
    if (!this.hasLinkBeenGenerated || !this.hasRoomIdBeenCreated) {
      return false;
    }
    if (!this.ownersUid || this.ownersUid.length <= 0) {
      return false;
    }
    return true;
  }

  private generateRoomId() {
    this.roomId = this.cryptoService.GenerateRandomString();
    this.hasRoomIdBeenCreated = true;
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
