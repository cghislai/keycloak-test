import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {environment} from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class HelloService {

  constructor(
    private httpClient: HttpClient
  ) {
  }

  getHello$() {
    return this.httpClient.get(`${environment.wsUrl}/hello`, {
      responseType: 'text'
    });
  }

}
