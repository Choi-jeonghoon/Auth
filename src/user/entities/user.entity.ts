import { Exclude } from 'class-transformer';
import { BaseTable } from 'src/common/entity/base-table.entuty';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

export enum Role {
  admin, //관리자
  paidUser, //결제한 사용자
  user, //일반 사용자
}

@Entity()
export class User extends BaseTable {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    unique: true,
  })
  email: string;

  @Column()
  @Exclude({
    toPlainOnly: true, //우리가 응답을 할때 (응답을 할때는 비밀번호정보를 안보여줄것이다. )
    //toClassOnly:,// 요청을 받을때 (요청은 비밀번호를 받을꺼니까 없어도 무방)
  })
  password: string;

  @Column({ enum: Role, default: Role.user })
  role: Role;
}
