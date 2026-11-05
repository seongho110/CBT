const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS 설정 (동적 Origin 허용)
app.use(cors({
    origin: true,
    credentials: true
}));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

app.use(express.json());
app.use(cookieParser());

// 루트 경로의 정적 파일(HTML, CSS, JS) 제공
app.use(express.static(path.join(__dirname)));

// JWT 인증 검증 미들웨어
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ isAuthenticated: false, message: '인증 토큰이 없습니다.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ isAuthenticated: false, message: '만료되었거나 유효하지 않은 토큰입니다.' });
        }
        req.user = user;
        next();
    });
};

/* ==========================================================================
   기본 페이지 라우트
   ========================================================================== */

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

/* ==========================================================================
   API 라우터 (인증)
   ========================================================================== */

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        if (!email || !password || !name) {
            return res.status(400).json({ message: '모든 항목을 입력해 주세요.' });
        }

        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .maybeSingle();

        if (existingUser) {
            return res.status(400).json({ message: '이미 가입된 이메일입니다.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const { error } = await supabase
            .from('users')
            .insert([{ email, password_hash: hashedPassword, name }]);

        if (error) throw error;
        res.status(201).json({ message: '회원가입이 완료되었습니다.' });
    } catch (err) {
        console.error('회원가입 에러:', err);
        res.status(500).json({ message: err.message || '서버 오류가 발생했습니다.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .maybeSingle();

        if (error || !user) {
            return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.json({ message: '로그인 성공', user: { name: user.name, email: user.email } });
    } catch (err) {
        console.error('로그인 에러:', err);
        res.status(500).json({ message: err.message || '서버 오류가 발생했습니다.' });
    }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({ isAuthenticated: true, user: req.user });
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: '로그아웃 되었습니다.' });
});

/* ==========================================================================
   CBT 문제 데이터 API
   ========================================================================== */

app.get('/api/questions/sessions', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cbt_questions')
            .select('exam_session');

        if (error) throw error;

        const sessions = [...new Set(data.map(item => item.exam_session).filter(Boolean))].sort().reverse();
        res.json({ sessions });
    } catch (err) {
        console.error('회차 목록 조회 에러:', err);
        res.status(500).json({ message: '회차 목록을 불러오지 못했습니다.' });
    }
});

app.get('/api/questions', async (req, res) => {
    try {
        const { session, subject_id } = req.query;
        let query = supabase.from('cbt_questions').select('*');

        if (session) {
            query = query.eq('exam_session', session);
        }
        if (subject_id) {
            query = query.eq('subject_id', subject_id);
        }

        const { data, error } = await query.order('id', { ascending: true });

        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error('문제 조회 에러:', err);
        res.status(500).json({ message: '문제를 불러오는데 실패했습니다.' });
    }
});

/* ==========================================================================
   오답 노트 백엔드 DB 연동 API
   ========================================================================== */

app.post('/api/wrong', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { question_id } = req.body;

        const { error } = await supabase
            .from('user_wrong_questions')
            .upsert([{ user_id: userId, question_id: question_id }], { onConflict: 'user_id,question_id' });

        if (error) throw error;
        res.json({ message: '오답이 등록되었습니다.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/wrong', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        const { data, error } = await supabase
            .from('user_wrong_questions')
            .select(`
                id,
                question_id,
                cbt_questions (*)
            `)
            .eq('user_id', userId);

        if (error) throw error;
        res.json(data.map(item => item.cbt_questions));
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.delete('/api/wrong/:questionId', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { questionId } = req.params;

        const { error } = await supabase
            .from('user_wrong_questions')
            .delete()
            .eq('user_id', userId)
            .eq('question_id', questionId);

        if (error) throw error;
        res.json({ message: '오답이 삭제되었습니다.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// 로컬 환경 실행
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`CBT 백엔드 서버 구동 중: http://localhost:${PORT}`);
    });
}

// Vercel 서버리스 내보내기
module.exports = app;