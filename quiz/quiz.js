// quiz.js

// Embaralha as perguntas e retorna as 10 primeiras

console.log("Perguntas carregadas:", quizData);

function getRandomQuestions(questions, total = 10) {
    const shuffled = questions.sort(() => 0.5 - Math.random());
    return shuffled.slice(0, total);
}

console.log("Perguntas carregadas:", quizData);  // Verifique se as perguntas estão carregando

const selectedQuestions = getRandomQuestions(quizData, 10);
let currentQuestion = 0;
let score = 0;
let difficultyScore = {
    Fácil: 0,
    Médio: 0,
    Difícil: 0
};

const questionElement = document.getElementById("question");
const optionsElement = document.getElementById("options");
const resultElement = document.getElementById("result");
const scoreElement = document.getElementById("score");

function loadQuestion() {
    if (currentQuestion < selectedQuestions.length) {
        const q = selectedQuestions[currentQuestion];
        questionElement.textContent = `${currentQuestion + 1}. (${q.difficulty}) ${q.question}`;
        optionsElement.innerHTML = "";
        q.options.forEach(option => {
            const button = document.createElement("button");
            button.textContent = option;
            button.onclick = () => checkAnswer(option);
            optionsElement.appendChild(button);
        });
    } else {
        showFinalResult();
    }
}

function checkAnswer(answer) {
    const q = selectedQuestions[currentQuestion];
    if (answer === q.answer) {
        resultElement.textContent = "✅ Resposta correta!";
        score++;
        difficultyScore[q.difficulty]++;
    } else {
        resultElement.textContent = `❌ Resposta errada! Resposta correta: ${q.answer}`;
    }
    currentQuestion++;
    setTimeout(() => {
        resultElement.textContent = "";
        loadQuestion();
    }, 1200);
}

function showFinalResult() {
    questionElement.textContent = "Quiz finalizado!";
    optionsElement.innerHTML = "";

    let feedback = "";
    if (score === 10) {
        feedback = "Excelente! Você acertou todas as perguntas! 🏆";
    } else if (score >= 8) {
        feedback = "Muito bom! Você mandou bem. 👍";
    } else if (score >= 5) {
        feedback = "Você foi bem, mas pode melhorar! 💪";
    } else {
        feedback = "É uma boa ideia revisar os conceitos de Segurança da Informação. 📘";
    }

    scoreElement.innerHTML = `
    <strong>Você acertou ${score} de 10 perguntas.</strong><br>
    Acertos por dificuldade:<br>
    ✅ Fácil: ${difficultyScore["Fácil"]}<br>
    ✅ Médio: ${difficultyScore["Médio"]}<br>
    ✅ Difícil: ${difficultyScore["Difícil"]}<br><br>
    <em>${feedback}</em>`;
}

loadQuestion();
