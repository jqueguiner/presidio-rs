// Manual E2E check for download-on-first-use. Run from a dir without ./data.
#[cfg(feature = "tickers-gazetteer")]
use presidio_analyzer::EntityRecognizer;

fn main() {
    #[cfg(feature = "tickers-gazetteer")]
    {
        let t = presidio_analyzer::gazetteer::stock_tickers();
        let hits = t.analyze("bought AAPL", &["STOCK_TICKER".to_string()], None);
        println!("loaded {} tickers; AAPL hits: {}", t.len(), hits.len());
    }
    #[cfg(not(feature = "tickers-gazetteer"))]
    println!("enable --features tickers-gazetteer");
}
