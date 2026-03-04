<div class="post-body">
<div id="links">
<style>
/* 友链容器样式 */
.link-navigation {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 1rem;
    max-width: 100%;
}
/* 通用卡片样式 */
.card {
    width: 100%;
    max-width: 320px;
    height: 90px;
    font-size: 1rem;
    padding: 10px 20px;
    border-radius: 25px;
    transition: transform 0.15s, box-shadow 0.15s, background 0.15s;
    display: flex;
    align-items: center;
    color: #333;
    justify-self: center;
}
.card:hover {
    transform: translateY(0px) scale(1.05);
    background-color: rgba(68, 138, 255, 0.1);
    color: #040000;
}
.card a {
    border: none;
}
.card .ava {
    width: 3rem !important;
    height: 3rem !important;
    margin: 0 !important;
    margin-right: 1em !important;
    border-radius: 50%;
}
.card .card-header {
    font-style: italic;
    overflow: hidden;
    width: auto;
}
.card .card-header a {
    font-style: normal;
    color: #608DBD;
    font-weight: bold;
    text-decoration: none;
}
.card .card-header a:hover {
    color: #d480aa;
    text-decoration: none;
}
.card .card-header .info {
    font-style: normal;
    color: #706f6f;
    font-size: 14px;
    min-width: 0;
    overflow: visible;
    white-space: normal;
}
/* 小屏优化 */
@media (max-width: 768px) {
    .link-navigation {
        grid-template-columns: 1fr;
        gap: 0.8rem;
    }
    .card {
        width: 100%;
        max-width: 100%;
        height: auto;
        min-height: 80px;
    }
    .card:hover {
        background-color: rgba(68, 138, 255, 0.1);
    }
}
</style>
<div class="links-content">
<div class="link-navigation">
    <div class="card">
        <img class="ava" src="https://www.imageoss.com/images/2025/08/31/_2025-08-31_154628_5697ba1eb627e156b0e.jpg" />
        <div class="card-header">
            <div>
                <a href="https://emotionaledm.github.io/" target="_blank">EmotionalEDM's Blog</a>
            </div>
            <div class="info">Where flowers bloom, where dreams come true.</div>
        </div>
    </div>
    <<div class="card">
        <img class="ava" src="../figures/ladygege.jpg" />
        <div class="card-header">
        <div>
            <a href="https://ladygege2494.github.io/" target="_blank">GegeNook</a>
        </div>
        <div class="info">不拘一格</div>
        </div>
    </div>>
    <!--<div class="card">
        <img class="ava" src="" />
        <div class="card-header">
        <div>
            <a href="{link}" target="_blank"></a>
        </div>
        <div class="info"></div>
        </div>
    </div> -->

</div>
</div>
</div>
</div>
