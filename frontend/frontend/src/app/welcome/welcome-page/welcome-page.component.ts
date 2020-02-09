import {Component, OnInit} from '@angular/core';
import {Observable} from 'rxjs';
import {HelloService} from '../hello.service';
import {publishReplay, refCount} from 'rxjs/operators';

@Component({
  selector: 'app-welcome-page',
  templateUrl: './welcome-page.component.html',
  styleUrls: ['./welcome-page.component.scss']
})
export class WelcomePageComponent implements OnInit {


  helloResponse$: Observable<string>;

  constructor(
    private helloService: HelloService,
  ) {
  }

  ngOnInit() {
    this.helloResponse$ = this.helloService.getHello$().pipe(
      publishReplay(1), refCount()
    );
  }

}
