import { Component, OnInit } from '@angular/core';
import { CryptoService } from 'src/app/services/crypto/crypto.service';
import { LinkGenerationService } from 'src/app/services/link-generation/link-generation.service';
import { LoginService } from 'src/app/services/login/login.service';
import { Observable } from 'rxjs';
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
  private roomId: string;
  constructor(
    private linkGenerationService: LinkGenerationService,
    private cryptoService: CryptoService,
    private loginService: LoginService
  ) {}

  ngOnInit(): void {}

  createSession() {
    this.generateRoomId();
    this.hasSessionBeenCreated = true;
  }

  joinSession() {
    if (!this.hasSessionBeenCreated) {
      // TODO show error notification
    }
    this.loginService.registerLoginCallback(this.ownersUid);
    this.loginService.login({
      uid: this.ownersUid,
      roomId: this.roomId,
      hash: this.linkGenerationService.createLinkHash({ uid: this.ownersUid, roomId: this.roomId })
    });
  }

  generateLink($event) {
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

  private generateRoomId() {
    this.roomId = this.cryptoService.GenerateRandomString();
  }

  togleLinkGeneration() {
    this.hasLinkBeenGenerated = !this.hasLinkBeenGenerated;
  }
}
