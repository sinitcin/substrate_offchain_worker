//! Тут привиден очень упрощенный и определенно НЕ готовый к релизу оракул для получения цены
//! BTC/USD.
//!
//! 	Offchain Worker (OCW) будет запускаться после каждого блока, получать текущую цену и создавать
//! транзакцию с информацией о цене для включения в блокчейн.
//! 	Логика on-chain будет просто агрегировать результаты и сохранять последние `64` значения для
//! вычисления средней цены.
//! 	В OCW реализована дополнительная логика для предотвращения спама сети как подписанными, так и
//! неподписанными транзакциями, а пользовательский `UnsignedValidator` следит за тем, чтобы в сети
//! появлялась только одна неподписанная транзакция.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::traits::Get;
use frame_system::{
	self as system,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendUnsignedTransaction, SignedPayload, Signer,
		SigningTypes,
	},
};
use lite_json::json::JsonValue;
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	offchain::{http, Duration},
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
	RuntimeDebug,
};
use sp_std::vec::Vec;

#[cfg(test)]
mod tests;

/// Определяет идентификатор приложения для криптографических ключей этого модуля.
///
/// 	Каждый модуль, работающий с подписями, должен объявить свой уникальный идентификатор для своих
/// криптографических ключей.
///  	Когда offchain worker подписывает транзакции, он будет запрашивать
/// ключи типа `KeyTypeId` из хранилища ключей и использовать найденные ключи для подписания
/// транзакции.
///  	Ключи могут быть вставлены вручную через RPC (см. `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"btc!");

/// На основе указанного выше `KeyTypeId` нам нужно сгенерировать обертки криптографических типов
/// Мы можем использовать все поддерживаемые типы криптографии (`sr25519`, `ed25519` и `ecdsa`) и
/// дополнить типы этим идентификатором для конкретной палетки.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
		MultiSignature, MultiSigner,
	};
	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;

	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// реализовано для moc-тестов
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	/// This pallet's configuration trait
	#[pallet::config]
	pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config {
		/// Тип идентификатора для OCW
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

		/// Тип события
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		// Параметры конфигурации

		/// Grace период после отправки транзакции.
		///
		/// Чтобы избежать отправки слишком большого количества транзакций, стараемся отправлять
		/// только одну транзакцию каждые `GRACE_PERIOD` блоков. Используем локальное хранилище
		/// для координации отправки между разными запусками OCW.
		#[pallet::constant]
		type GracePeriod: Get<Self::BlockNumber>;

		/// Количество пропускаемых блоков после включения неподписанной транзакции.
		///
		/// Гарантирует, что мы принимаем неподписанные транзакции только один раз, каждый
		/// ``UnsignedInterval`` блоков.
		#[pallet::constant]
		type UnsignedInterval: Get<Self::BlockNumber>;

		/// Конфигурация приоритета неподписанных транзакций.
		///
		/// Используется для конкретного runtime, когда несколько паллет отправляют
		/// неподписанные транзакции.
		#[pallet::constant]
		type UnsignedPriority: Get<TransactionPriority>;

		/// Максимальное количество цен.
		#[pallet::constant]
		type MaxPrices: Get<u32>;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Обьявление Offchain Worker.
		///
		/// Реализуя `fn offchain_worker`, объявляем новый OCW.
		/// Эта функция будет вызвана, когда нода полностью синхронизирована и новый лучший блок
		/// успешно импортирован.
		///
		/// ВНИМАНИЕ: Нет гарантии, что OCW будет работать на КАЖДОМ блоке, могут быть случаи, когда
		/// некоторые блоки пропускаются, или для некоторых OCW запускается дважды (re-orgs),
		/// поэтому код должен быть в состоянии справиться с этим. Вы можете использовать API `Local
		/// Storage` для координации запусков OCW.
		fn offchain_worker(block_number: T::BlockNumber) {
			// Компиляция логов в WASM может привести к значительному
			// увеличению размера блоба. Можно использовать пользовательскую функцию
			// `RuntimeDebug`, чтобы скрыть детали в WASM. Крейт `sp-api` также предоставляет
			// функцию `disable-logging` для отключения протоколирования в целом в WASM.
			log::info!("Hello World from offchain workers!");

			let parent_hash = <system::Pallet<T>>::block_hash(block_number - 1u32.into());
			log::debug!("Current block: {:?} (parent hash: {:?})", block_number, parent_hash);

			// Хорошей практикой является сохранение минимальной функции `fn offchain_worker()` и
			// перемещение большей части кода в отдельный блок `impl`.

			// Здесь мы вызываем вспомогательную функцию для вычисления текущей средней цены.  Эта
			// функция считывает записи из хранилища текущего состояния.
			let average: Option<u32> = Self::average_price();
			log::debug!("Current price: {:?}", average);

			if let Err(e) = Self::fetch_price_and_send_unsigned_for_all_accounts(block_number) {
				log::error!("Error: {}", e);
			}
		}
	}

	/// Публичная часть палетки.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Внесение новой цены в список с помощью неподписанной транзакции.
		///
		/// Поскольку мы разрешаем отправлять транзакцию без подписи, а значит, без уплаты
		/// каких-либо комиссий, нам нужен способ убедиться, что принимаются только некоторые
		/// транзакции. Эта функция может быть вызвана только один раз через каждые
		/// `T::UnsignedInterval` блоков.Транзакции, вызывающие эту функцию, де-дублируются на
		/// уровне пула через `validate_unsigned`, а также становятся недействительными,
		/// если функция уже была вызвана в текущей "сессии". Важно также указать `weight` для
		/// неподписанных вызовов, потому что, хотя они и не взимают плату, мы все равно не хотим,
		/// чтобы один блок содержал неограниченное количество таких транзакций.

		#[pallet::call_index(0)]
		#[pallet::weight({0})]
		pub fn submit_price_unsigned_with_signed_payload(
			origin: OriginFor<T>,
			price_payload: PricePayload<T::Public, T::BlockNumber>,
			_signature: T::Signature,
		) -> DispatchResultWithPostInfo {
			// Гарантирует, что функция может быть вызвана только через неподписанную
			// транзакцию.
			ensure_none(origin)?;
			// Добавление цены в список on-chain, но с пометкой как пришедшую с пустого адреса.
			Self::add_price(None, price_payload.price);
			// Теперь увеличиваем номер блока, в котором мы ожидаем следующую неподписанную
			// транзакцию.
			let current_block = <system::Pallet<T>>::block_number();
			<NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());
			Ok(().into())
		}
	}

	/// События палетки.
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Событие, генерируемое, когда новая цена получена
		NewPrice { price: u32, maybe_who: Option<T::AccountId> },
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		/// Проверка неподписанного вызова
		///
		/// По умолчанию неподписанные транзакции запрещены, но, применяя здесь валидатор, мы
		/// убеждаемся, что некоторые конкретные вызовы (те, которые производит offchain worker)
		/// попадают в белый список и помечаются как допустимые.
		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			// Прежде всего, давайте проверим, что мы вызываем правильную функцию.
			if let Call::submit_price_unsigned_with_signed_payload {
				price_payload: ref payload,
				ref signature,
			} = call
			{
				let signature_valid =
					SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone());
				if !signature_valid {
					return InvalidTransaction::BadProof.into()
				}
				Self::validate_transaction_parameters(&payload.block_number, &payload.price)
			} else {
				InvalidTransaction::Call.into()
			}
		}
	}

	/// Вектор последних цен.
	///
	/// Используется для расчета средней цены, должен иметь ограниченный размер.
	#[pallet::storage]
	#[pallet::getter(fn prices)]
	pub(super) type Prices<T: Config> = StorageValue<_, BoundedVec<u32, T::MaxPrices>, ValueQuery>;

	/// Определяет блок, когда будет принята следующая неподписанная транзакция.
	///
	/// Чтобы предотвратить спам неподписанных (и неоплаченных!) транзакций в сети, мы разрешаем
	/// только одну транзакцию каждые `T::UnsignedInterval` блоков. Эта запись в хранилище
	/// определяет, когда будет принята новая транзакция.
	#[pallet::storage]
	#[pallet::getter(fn next_unsigned_at)]
	pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;
}

/// Необходимо для отправки транзакции.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct PricePayload<Public, BlockNumber> {
	block_number: BlockNumber,
	price: u32,
	public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for PricePayload<T::Public, T::BlockNumber> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

impl<T: Config> Pallet<T> {
	/// Вспомогательная функция для получения цены, подписания payload и отправки
	/// неподписанной транзакции
	fn fetch_price_and_send_unsigned_for_all_accounts(
		block_number: T::BlockNumber,
	) -> Result<(), &'static str> {
		// Убедимся, что мы не получаем цену, если неподписанная транзакция все равно будет
		// отклонена.
		let next_unsigned_at = <NextUnsignedAt<T>>::get();
		if next_unsigned_at > block_number {
			return Err("Too early to send unsigned transaction")
		}

		// HTTP-запрос для получения текущей цены. Этот вызов будет блокироваться до получения
		// ответа.
		let price = Self::fetch_price().map_err(|_| "Failed to fetch price")?;

		// -- Подписать, используя все учетные записи
		let transaction_results = Signer::<T, T::AuthorityId>::all_accounts()
			.send_unsigned_transaction(
				|account| PricePayload { price, block_number, public: account.public.clone() },
				|payload, signature| Call::submit_price_unsigned_with_signed_payload {
					price_payload: payload,
					signature,
				},
			);
		for (_account_id, result) in transaction_results.into_iter() {
			if result.is_err() {
				return Err("Unable to submit transaction")
			}
		}

		Ok(())
	}

	/// Получение текущей цены и возврат результата в центах.
	fn fetch_price() -> Result<u32, http::Error> {
		// Желательно, чтобы время выполнения Offchain Worker было разумным, поэтому устанавливаем
		// жестко заданный срок в 2с для завершения внешнего вызова. Вы также можете ждать ответа
		// неограниченное время, но при этом вы можете получить тайм-аут от хост-машины.
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		// Инициирование внешнего HTTP GET запроса. Здесь используются высокоуровневые обертки из
		// `sp_runtime` для низкоуровневых вызовов, которые можно найти в `sp_io`. API пытается
		// быть похожим на `request`, но поскольку работаем в WASM, мы не можем просто импортировать
		// библиотеку `request`.
		let request =
			http::Request::get("https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD");
		// Устанавливаем срок отправки запроса, обратите внимание, что ожидание ответа может
		// иметь отдельный срок. Далее мы отправляем запрос, перед этим также можно изменить
		// заголовки запроса или содержимое тела потока в случае не-GET запросов.
		let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;

		// Запрос уже обрабатывается хостом, мы можем делать все остальное в OCW (мы можем
		// посылать несколько одновременных запросов). Однако в какой-то момент, вероятно,
		// захотим проверить ответ, поэтому мы можем заблокировать текущий поток и дождаться его
		// завершения. Обратите внимание, что поскольку запрос выполняется хостом, нам не нужно
		// ждать его завершения, мы просто не будем читать ответ.
		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		// Давайте проверим код состояния, прежде чем перейти к чтению ответа.
		if response.code != 200 {
			log::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown)
		}

		// Далее мы хотим полностью прочитать тело ответа и собрать его в вектор байтов. Объект
		// response позволяет читать тело кусками, а также контролировать таймауты.
		let body = response.body().collect::<Vec<u8>>();

		let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
			log::warn!("No UTF8 body");
			http::Error::Unknown
		})?;

		let price = match Self::parse_price(body_str) {
			Some(price) => Ok(price),
			None => {
				log::warn!("Unable to extract price from the response: {:?}", body_str);
				Err(http::Error::Unknown)
			},
		}?;

		log::warn!("Got price: {} cents", price);

		Ok(price)
	}

	/// Парсинг цены из заданной строки JSON с помощью `lite-json`.
	///
	/// Возвращает `None` при неудачном парсинге или `Some(price in cents)` при успешном разборе.
	fn parse_price(price_str: &str) -> Option<u32> {
		let val = lite_json::parse_json(price_str);
		let price = match val.ok()? {
			JsonValue::Object(obj) => {
				let (_, v) = obj.into_iter().find(|(k, _)| k.iter().copied().eq("USD".chars()))?;
				match v {
					JsonValue::Number(number) => number,
					_ => return None,
				}
			},
			_ => return None,
		};

		let exp = price.fraction_length.saturating_sub(2);
		Some(price.integer as u32 * 100 + (price.fraction / 10_u64.pow(exp)) as u32)
	}

	/// Добавление новой цены в список.
	fn add_price(maybe_who: Option<T::AccountId>, price: u32) {
		log::info!("Adding to the average: {}", price);
		<Prices<T>>::mutate(|prices| {
			if prices.try_push(price).is_err() {
				prices[(price % T::MaxPrices::get()) as usize] = price;
			}
		});

		let average = Self::average_price()
			.expect("The average is not empty, because it was just mutated; qed");
		log::info!("Current average price is: {}", average);
		// here we are raising the NewPrice event
		Self::deposit_event(Event::NewPrice { price, maybe_who });
	}

	/// Рассчитываем текущую среднюю цену.
	fn average_price() -> Option<u32> {
		let prices = <Prices<T>>::get();
		if prices.is_empty() {
			None
		} else {
			Some(prices.iter().fold(0_u32, |a, b| a.saturating_add(*b)) / prices.len() as u32)
		}
	}

	fn validate_transaction_parameters(
		block_number: &T::BlockNumber,
		new_price: &u32,
	) -> TransactionValidity {
		// Теперь давайте проверим, есть ли у транзакции шансы на успех.
		let next_unsigned_at = <NextUnsignedAt<T>>::get();
		if &next_unsigned_at > block_number {
			return InvalidTransaction::Stale.into()
		}
		// Давайте позаботимся о том, чтобы отклонить транзакции из будущего.
		let current_block = <system::Pallet<T>>::block_number();
		if &current_block < block_number {
			return InvalidTransaction::Future.into()
		}

		// Мы отдаем приоритет сделкам, которые более далеки от текущего среднего уровня.
		//
		// Обратите внимание, что это не имеет особого смысла при построении реального оракула.
		let avg_price = Self::average_price()
			.map(|price| if &price > new_price { price - new_price } else { new_price - price })
			.unwrap_or(0);

		ValidTransaction::with_tag_prefix("ExampleOffchainWorker")
			// Мы устанавливаем базовый приоритет 2**20 и надеемся, что он будет включен раньше
			// других транзакций в пуле. Далее мы изменяем приоритет в зависимости от того,
			// насколько сильно он отличается от текущего среднего. (чем больше разница, тем больше
			// приоритет). имеет).
			.priority(T::UnsignedPriority::get().saturating_add(avg_price as _))
			// Эта транзакция не требует, чтобы перед ней в пул попала какая-либо другая.
			// Теоретически мы могли бы потребовать, чтобы первой шла транзакция
			// `previous_unsigned_at`, но в нашем случае в этом нет необходимости.
			// .and_requires()
			// Мы устанавливаем тег `provides` таким же, как `next_unsigned_at`. Это позволяет что
			// только одна транзакция, произведенная после `next_unsigned_at`, когда-либо попадет в
			// пул транзакций и окажется в блоке. Мы все еще можем иметь несколько транзакций,
			// конкурирующих за одно и то же "место", и транзакция с более высоким приоритетом
			// заменит другую в пуле.
			.and_provides(next_unsigned_at)
			// Транзакция действительна только в течение следующих 5 блоков. После этого она будет
			// повторно подтверждена пулом.
			.longevity(5)
			// Эту транзакцию можно распространять среди других пиров, что означает, что она может
			// быть создана даже узлами, которые не производят блоки. Обратите внимание, что иногда
			// лучше оставить ее для себя (если вы являетесь производителем блоков), поскольку,
			// например, в некоторых схемах другие могут скопировать ваше решение и потребовать
			// вознаграждение.
			.propagate(true)
			.build()
	}
}
