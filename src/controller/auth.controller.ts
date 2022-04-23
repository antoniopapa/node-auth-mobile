import {Request, Response} from "express";
import {getRepository, MoreThanOrEqual} from "typeorm";
import {User} from "../entity/user.entity";
import bcryptjs from 'bcryptjs';
import {sign, verify} from 'jsonwebtoken';
import {Token} from "../entity/token.entity";

export const Register = async (req: Request, res: Response) => {
    const body = req.body;

    if (body.password !== body.password_confirm) {
        return res.status(400).send({
            message: "Password's do not match!"
        });
    }

    const {password, ...user} = await getRepository(User).save({
        first_name: body.first_name,
        last_name: body.last_name,
        email: body.email,
        password: await bcryptjs.hash(body.password, 12),
    });

    res.send(user);
}

export const Login = async (req: Request, res: Response) => {
    const user = await getRepository(User).findOne({email: req.body.email});

    if (!user) {
        return res.status(400).send({
            message: 'Invalid credentials'
        })
    }

    if (!await bcryptjs.compare(req.body.password, user.password)) {
        return res.status(400).send({
            message: 'Invalid credentials'
        })
    }

    const refresh = sign({
        id: user.id
    }, process.env.REFRESH_SECRET || '', {expiresIn: '1w'});

    const expired_at = new Date();
    expired_at.setDate(expired_at.getDate() + 7);

    await getRepository(Token).save({
        user_id: user.id,
        token: refresh,
        expired_at
    });

    const access = sign({id: user.id}, process.env.ACCESS_SECRET || '', {expiresIn: '2m'});

    res.send({
        access,
        refresh
    });
}

export const AuthenticatedUser = async (req: Request, res: Response) => {
    try {
        const accessToken = req.header('Authorization')?.split(' ')[1] || '';

        const payload: any = verify(accessToken, process.env.ACCESS_SECRET || '');

        if (!payload) {
            return res.status(401).send({
                message: 'unauthenticated'
            });
        }

        const user = await getRepository(User).findOne(payload.id);

        if (!user) {
            return res.status(401).send({
                message: 'unauthenticated'
            });
        }

        const {password, ...data} = user;

        res.send(data);
    } catch (e) {
        return res.status(401).send({
            message: 'unauthenticated'
        });
    }
}

export const Refresh = async (req: Request, res: Response) => {
    try {
        const {token} = req.body;

        const payload: any = verify(token, process.env.REFRESH_SECRET || '');

        if (!payload) {
            return res.status(401).send({
                message: 'unauthenticated'
            });
        }

        const refresh = await getRepository(Token).findOne({
            user_id: payload.id,
            expired_at: MoreThanOrEqual(new Date())
        });

        if (!refresh) {
            return res.status(401).send({
                message: 'unauthenticated'
            });
        }

        const access = sign({
            id: payload.id
        }, process.env.ACCESS_SECRET || '', {expiresIn: '2m'});

        res.send({
            access,
            refresh
        });
    } catch (e) {
        return res.status(401).send({
            message: 'unauthenticated'
        });
    }
}

export const Logout = async (req: Request, res: Response) => {
    await getRepository(Token).delete({
        token: req.cookies['refresh_token']
    });

    res.send({
        message: 'success'
    });
}
