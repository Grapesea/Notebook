## Web端简易代码

??? tips "创建虚拟连接并下载pdf"

    ```js
    function downloadArxivPdf(articleId, filename) {
        const pdfUrl = `https://arxiv.org/pdf/${articleId}`;
        
        // 1. 创建一个临时的 <a> 标签
        const link = document.createElement('a');
        
        // 2. 设置下载链接
        link.href = pdfUrl;
        
        // 3. 设置下载文件名（可选，但推荐）
        link.download = filename || `${articleId}.pdf`; 
        
        // 4. 将链接添加到文档中（必须步骤，以便在某些浏览器中生效）
        document.body.appendChild(link);
        
        // 5. 模拟点击以触发下载
        link.click();
        
        // 6. 清理临时标签
        document.body.removeChild(link);
    }

    // 示例调用：
    downloadArxivPdf('2412.08923', 'My-Paper-2412.08923.pdf');
    ```
